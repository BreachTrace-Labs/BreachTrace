"""Write-only encrypted project credential connections."""
from __future__ import annotations

import json
import re
import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from access import assert_project_access
from auth import require_admin_or_lead
from crypto import encrypt_blob
from db.database import get_db
from db.models import CredentialWalletEntry, User
from audit import record
from wallet_verify import verify_entry

router = APIRouter(prefix='/projects/{project_id}/wallet', tags=['credential wallet'])
Provider = Literal['aws', 'gcp', 'azure', 'stripe', 'twilio']


class WalletInput(BaseModel):
    provider: Provider
    label: str | None = Field(default=None, max_length=80)
    credentials: dict[str, str] = Field(max_length=8)


def validate_credentials(provider: str, values: dict[str, str]) -> dict[str, str]:
    required = {
        'aws': {'access_key_id', 'secret_access_key', 'region'},
        'gcp': {'service_account_json'},
        'azure': {'tenant_id', 'client_id', 'client_secret', 'subscription_id'},
        'stripe': {'api_key'},
        'twilio': {'account_sid', 'auth_token'},
    }[provider]
    if set(values) != required or any(not v.strip() or len(v) > 50000 for v in values.values()):
        raise HTTPException(422, 'Provide the required credential fields for the selected provider')
    if provider == 'stripe' and not re.fullmatch(r'rk_(test|live)_[A-Za-z0-9]+', values['api_key']):
        raise HTTPException(422, 'Use a Stripe restricted test or live key')
    if provider == 'twilio' and not re.fullmatch(r'AC[0-9a-fA-F]{32}', values['account_sid']):
        raise HTTPException(422, 'Twilio Account SID must start with AC and contain 32 hexadecimal characters')
    if provider == 'aws' and (not re.fullmatch(r'AKIA[A-Z0-9]{16}', values['access_key_id']) or
                              not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d+', values['region'])):
        raise HTTPException(422, 'Invalid AWS access key ID or region')
    if provider == 'azure':
        try:
            for key in ('tenant_id', 'client_id', 'subscription_id'):
                uuid.UUID(values[key])
        except ValueError:
            raise HTTPException(422, 'Azure tenant, client, and subscription IDs must be UUIDs')
    if provider == 'gcp':
        try:
            info = json.loads(values['service_account_json'])
            if not isinstance(info, dict) or info.get('type') != 'service_account' or not all(info.get(k) for k in ('project_id', 'private_key', 'client_email', 'token_uri')):
                raise ValueError()
            # Service account token URLs must target Google's OAuth service.
            if info['token_uri'] != 'https://oauth2.googleapis.com/token':
                raise ValueError()
        except (ValueError, TypeError):
            raise HTTPException(422, 'Provide a valid Google service account JSON with a project ID')
    return values


def public(entry: CredentialWalletEntry):
    return {'id': entry.id, 'provider': entry.provider, 'label': entry.label,
            'verification_status': entry.verification_status, 'verification_error': entry.verification_error,
            'last_verified_at': entry.last_verified_at, 'created_at': entry.created_at}


def get_entry(db: Session, project_id: str, entry_id: str):
    entry = db.query(CredentialWalletEntry).filter_by(project_id=project_id, id=entry_id).first()
    if not entry:
        raise HTTPException(404, 'Wallet entry not found')
    return entry


@router.get('')
def list_entries(project_id: str, user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    return [public(row) for row in db.query(CredentialWalletEntry).filter_by(project_id=project_id).order_by(CredentialWalletEntry.provider).all()]


@router.post('', status_code=202)
def save_entry(project_id: str, body: WalletInput, request: Request, tasks: BackgroundTasks,
               user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    values = validate_credentials(body.provider, body.credentials)
    try:
        ciphertext, iv = encrypt_blob(values)
    except Exception:
        raise HTTPException(503, 'Wallet encryption is not configured correctly') from None
    entry = db.query(CredentialWalletEntry).filter_by(project_id=project_id, provider=body.provider).first()
    if entry is None:
        entry = CredentialWalletEntry(project_id=project_id, provider=body.provider, created_by=user.id,
                                      encrypted_blob=ciphertext, iv=iv)
        db.add(entry)
    else:
        entry.encrypted_blob, entry.iv, entry.created_by = ciphertext, iv, user.id
    entry.label = body.label.strip() if body.label else None
    entry.verification_status = 'pending'
    entry.verification_error = None
    entry.last_verified_at = None
    try:
        db.flush()
        record(db, user, 'wallet.created', request, project_id=project_id, detail={'provider': body.provider})
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'Connection was modified concurrently; try again')
    tasks.add_task(verify_entry, entry.id, iv, user.id)
    return public(entry)


@router.post('/{entry_id}/verify', status_code=202)
def reverify(project_id: str, entry_id: str, request: Request, tasks: BackgroundTasks,
             user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    entry = get_entry(db, project_id, entry_id)
    entry.verification_status = 'pending'
    entry.verification_error = None
    record(db, user, 'wallet.verification_requested', request, project_id=project_id, detail={'provider': entry.provider})
    db.commit()
    tasks.add_task(verify_entry, entry.id, entry.iv, user.id)
    return {'status': 'pending'}


@router.delete('/{entry_id}')
def delete_entry(project_id: str, entry_id: str, request: Request,
                 user: User = Depends(require_admin_or_lead), db: Session = Depends(get_db)):
    assert_project_access(project_id, user, db)
    entry = get_entry(db, project_id, entry_id)
    record(db, user, 'wallet.deleted', request, project_id=project_id, detail={'provider': entry.provider})
    db.delete(entry)
    db.commit()
    return {'message': 'Connection removed'}
