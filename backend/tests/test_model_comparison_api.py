from fastapi import FastAPI
from fastapi.testclient import TestClient
from db.database import get_db
from routers import research


def test_comparison_uses_only_installed_models_and_prevents_overlapping_jobs(sqlite_factory, monkeypatch):
    app=FastAPI(); app.include_router(research.router)
    def database():
        with sqlite_factory() as db: yield db
    app.dependency_overrides[get_db]=database
    monkeypatch.setattr(research, 'installed_ollama_models', lambda: [{'name':'local-a','size':1,'digest':'test'}])
    with TestClient(app, base_url='http://localhost', client=('127.0.0.1',1234)) as client:
        assert client.post('/research/model-benchmark',json={'models':['not-installed']}).status_code == 422
        response=client.post('/research/model-benchmark',json={'models':['local-a'],'cases':2})
        assert response.status_code == 202
        assert client.get('/research/model-benchmark/latest').json()['status']=='queued'
        assert client.post('/research/model-benchmark',json={'models':['local-a']}).status_code == 409
        assert client.post('/research/model-benchmark',json={'models':['local-a'],'cases':13}).status_code == 422
    with TestClient(app, base_url='http://remote.example', client=('203.0.113.1',1234)) as remote:
        assert remote.get('/research/model-benchmark/models').status_code == 403
