import uuid

import pytest

from backend.app.models.enums import UserRole, UserStatus
from backend.app.models.user import User
from tests.test_phase5_verification import register_and_login_user


@pytest.fixture
def directory(client, db_session):
    auth = register_and_login_user(client, 'lookup-owner@cyber.edu')
    first = User(id=str(uuid.uuid4()), full_name='Đặng Minh An', email='minh.an@cyber.edu',
        password_hash='not-a-login-hash', role=UserRole.USER, status=UserStatus.ACTIVE)
    second = User(id=str(uuid.uuid4()), full_name='Trần Bình', email='binh_tran@cyber.edu',
        password_hash='not-a-login-hash', role=UserRole.USER, status=UserStatus.DISABLED)
    db_session.add_all([first, second])
    db_session.commit()
    return auth, first.id, second.id


def test_user_lookup_requires_login(client):
    assert client.get('/api/v1/users/search', params={'q': 'minh'}).status_code == 401


@pytest.mark.parametrize('query', ['đẶNG mINH', 'MINH.AN@CYBER.EDU', '  minh.an  '])
def test_user_lookup_name_email_and_unicode(client, directory, query):
    auth, first_id, _ = directory
    response = client.get('/api/v1/users/search', params={'q': query}, headers=auth['headers'])
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['total'] == 1 and data['items'][0]['id'] == first_id
    assert set(data['items'][0]) == {'id', 'full_name', 'email', 'status'}
    assert response.headers['Cache-Control'] == 'no-store'


def test_user_lookup_uuid_status_and_unknown(client, directory):
    auth, _, disabled_id = directory
    response = client.get('/api/v1/users/search', params={'q': disabled_id.upper()}, headers=auth['headers'])
    assert response.status_code == 200, response.text
    assert response.json()['items'][0]['id'] == disabled_id
    assert response.json()['items'][0]['status'] == 'DISABLED'
    response = client.get('/api/v1/users/search', params={'q': str(uuid.uuid4())}, headers=auth['headers'])
    assert response.json()['items'] == [] and response.json()['total'] == 0


@pytest.mark.parametrize('params', [{'q':''}, {'q':'a'}, {'q':'  '}, {'q':'x'*256},
    {'q':'minh', 'limit':51}, {'q':'minh', 'limit':0}, {'q':'minh', 'offset':-1}])
def test_user_lookup_validation(client, directory, params):
    auth, _, _ = directory
    assert client.get('/api/v1/users/search', params=params, headers=auth['headers']).status_code == 422


def test_user_lookup_literal_wildcards_and_pagination(client, directory):
    auth, _, second_id = directory
    for query in ['%%', '__', "%' OR 1=1 --"]:
        response = client.get('/api/v1/users/search', params={'q':query}, headers=auth['headers'])
        assert response.status_code == 200 and response.json()['total'] == 0
    response = client.get('/api/v1/users/search', params={'q':'binh_'}, headers=auth['headers'])
    assert response.json()['items'][0]['id'] == second_id
    first = client.get('/api/v1/users/search', params={'q':'cyber.edu', 'limit':1}, headers=auth['headers']).json()
    second = client.get('/api/v1/users/search', params={'q':'cyber.edu', 'limit':1, 'offset':1}, headers=auth['headers']).json()
    assert first['total'] == second['total'] == 3
    assert len(first['items']) == len(second['items']) == 1
    assert first['items'][0]['id'] != second['items'][0]['id']
    assert second['offset'] == 1 and second['limit'] == 1
