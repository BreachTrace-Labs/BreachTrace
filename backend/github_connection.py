"""Project-scoped GitHub access; saved tokens never leave the backend."""
from crypto import decrypt_blob
from db.models import ProjectGitHubConnection


def project_token(db, project_id):
    row = db.get(ProjectGitHubConnection, project_id)
    if row is None:
        return None
    try:
        return decrypt_blob(row.encrypted_blob, row.iv)['token']
    except Exception:
        raise ValueError('The project GitHub connection could not be decrypted. Save the connection again.') from None
