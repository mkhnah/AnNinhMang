"""Admin authorization, stable audit pages, metric boundaries and alert isolation."""
from datetime import datetime, timedelta, timezone
import json
import uuid

import pytest
from sqlalchemy import select, update

from backend.app.models.audit import AuditLog
from backend.app.models.document import Document
from backend.app.models.enums import KeyStatus, UserRole
from backend.app.models.key import PublicKey
from backend.app.models.user import User
from backend.app.models.verification import VerificationEvent
from backend.app.services.audit_service import append_audit, request_context
from tests.test_phase5_verification import (
    create_and_sign_document, generate_test_rsa_3072, register_and_login_user, register_user_key,
)


@pytest.fixture
def admin(client, db_session):
    auth = register_and_login_user(client, 'audit-admin@cyber.edu')
    db_session.execute(update(User).where(User.id == auth['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    return auth


@pytest.mark.parametrize('path', ['/audit/logs', '/audit/verify-chain', '/dashboard/stats'])
def test_admin_endpoints_require_authentication_and_role(client, db_session, path):
    assert client.get('/api/v1' + path).status_code == 401
    auth = register_and_login_user(client, 'ordinary@cyber.edu')
    assert client.get('/api/v1' + path, headers=auth['headers']).status_code == 403
    db_session.execute(update(User).where(User.id == auth['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    response = client.get('/api/v1' + path, headers=auth['headers'])
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'


def test_log_pagination_stays_on_snapshot_when_new_events_arrive(client, db_session, admin):
    for _ in range(25):
        append_audit(db_session, 'USER_LOGIN', actor_id=admin['user_id'], target_type='USER')
    db_session.commit()
    first = client.get('/api/v1/audit/logs?limit=20', headers=admin['headers']).json()
    append_audit(db_session, 'USER_LOGIN', actor_id=admin['user_id'], target_type='USER')
    db_session.commit()
    second = client.get('/api/v1/audit/logs', params={
        'limit': 20, 'offset': 20, 'snapshot_id': first['snapshot_id'],
    }, headers=admin['headers']).json()
    assert len(first['items']) == 20 and len(second['items']) == 6
    assert first['total'] == second['total'] == 26
    ids = [row['id'] for row in first['items'] + second['items']]
    assert len(set(ids)) == 26 and all(isinstance(value, str) for value in ids)
    fresh = client.get('/api/v1/audit/logs?limit=1', headers=admin['headers']).json()
    assert fresh['total'] == 27 and fresh['snapshot_id'] != first['snapshot_id']


def test_log_filters_and_safe_detail_projection(client, db_session, admin):
    event = append_audit(db_session, 'KEY_GENERATE', actor_id=admin['user_id'], target_type='KEY',
                         target_id='test-key', details={'algorithm': 'RSA-PSS-3072'},
                         context=request_context('127.0.0.2', 'Firefox/1'))
    event_id = event.id
    db_session.commit()
    db_session.execute(update(AuditLog).where(AuditLog.id == event_id).values(details_json=json.dumps({
        'algorithm': 'RSA-PSS-3072', 'private_key': 'secret-must-be-removed',
    })))
    db_session.commit()
    now = datetime.now(timezone.utc)
    response = client.get('/api/v1/audit/logs', params={
        'action': 'KEY_GENERATE', 'actor_id': admin['user_id'], 'target_id': 'test-key',
        'status': 'SUCCESS', 'client_ip': '127.0.0.2',
        'since': (now - timedelta(minutes=1)).isoformat(), 'until': (now + timedelta(minutes=1)).isoformat(),
    }, headers=admin['headers'])
    assert response.status_code == 200
    row = response.json()['items'][0]
    assert row['details'] == {'algorithm': 'RSA-PSS-3072'} and not row['details_valid']
    assert 'secret-must-be-removed' not in response.text and 'details_json' not in response.text
    assert row['created_at'].endswith('Z')
    checked = client.get('/api/v1/audit/verify-chain', headers=admin['headers']).json()
    assert not checked['valid'] and checked['error_id'] == str(event_id)


@pytest.mark.parametrize('params', [
    {'limit': 101}, {'offset': -1}, {'offset': 2**63}, {'snapshot_id': -1}, {'action': 'BOGUS'}, {'status': 'BOGUS'},
    {'actor_id': 'x' * 37}, {'client_ip': 'bad-ip'}, {'since': '2026-11-16T00:00:00'},
    {'since': '2026-11-17T00:00:00Z', 'until': '2026-11-16T00:00:00Z'},
])
def test_invalid_log_filters_are_rejected(client, admin, params):
    assert client.get('/api/v1/audit/logs', params=params, headers=admin['headers']).status_code == 422


def test_log_list_survives_malformed_json_and_preserves_large_ids(client, db_session, admin):
    large_id = 2**53 + 1
    db_session.execute(update(AuditLog).values(id=large_id, details_json='{"malformed":'))
    db_session.commit()
    response = client.get('/api/v1/audit/logs', headers=admin['headers'])
    assert response.status_code == 200
    assert response.json()['items'][0]['id'] == str(large_id)
    assert response.json()['snapshot_id'] == str(large_id)
    assert response.json()['items'][0]['details'] == {}


def verification_event(db, summary, created_at):
    event = VerificationEvent(
        id=str(uuid.uuid4()), verification_mode='INDEPENDENT_DETACHED', summary_status=summary,
        cryptographic_validity='VALID', document_integrity='UNCHANGED', key_ownership='UNKNOWN',
        certificate_trust='SELF_REGISTERED', key_revocation_status='UNKNOWN', created_at=created_at,
    )
    db.add(event)


def test_dashboard_empty_and_time_bounded_statistics(client, db_session, admin):
    initial = client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()
    assert initial['verification_total'] == 0 and initial['verification_success_rate'] is None
    assert len(initial['verification_daily']) == 7 and initial['alert_total'] == 0
    now = datetime.now(timezone.utc)
    for summary, age in [('VERIFIED', 0), ('VERIFIED', 4), ('UNVERIFIABLE', 0), ('SIGNATURE_INVALID', 0), ('VERIFIED', 31), ('VERIFIED', -2)]:
        verification_event(db_session, summary, now - timedelta(days=age))
    db_session.add(Document(owner_id=admin['user_id'], title='Example'))
    for number, status, revoked_at in [(1, KeyStatus.ACTIVE, None), (2, KeyStatus.REVOKED, now), (3, KeyStatus.ACTIVE, now)]:
        db_session.add(PublicKey(user_id=admin['user_id'], algorithm='RSA-PSS-3072', spki_pem='synthetic',
                                 fingerprint=f'{number:064x}', status=status, revoked_at=revoked_at))
    db_session.commit()
    response = client.get('/api/v1/dashboard/stats', headers=admin['headers'])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['verification_total'] == 4 and result['verification_success_rate'] == 50
    assert result['total_documents'] == 1 and result['active_keys'] == 1
    assert sum(day['verified'] + day['unsuccessful'] for day in result['verification_daily']) == 4
    assert sum(row['count'] for row in result['verification_counts']) == 4


def audit_verification(db, summary, actor_id=None, peer='127.0.0.10'):
    return append_audit(db, 'DOCUMENT_VERIFY', actor_id=actor_id, target_type='VERIFICATION',
                        details={'summary_status': summary}, context=request_context(peer))


def test_alert_streak_isolated_by_subject_and_reset_by_success(client, db_session, admin):
    for _ in range(3):
        audit_verification(db_session, 'SIGNATURE_INVALID', peer='127.0.0.10')
    for _ in range(2):
        audit_verification(db_session, 'UNVERIFIABLE', peer='127.0.0.11')
    db_session.commit()
    result = client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()
    assert result['alert_total'] == 1
    assert result['alerts'][0]['client_ip'] == '127.0.0.10' and result['alerts'][0]['count'] == 3
    assert result['alerts'][0]['last_at'].endswith('Z')
    audit_verification(db_session, 'VERIFIED', peer='127.0.0.10')
    db_session.commit()
    assert client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()['alert_total'] == 0


def test_alerts_group_actor_across_ips_and_flag_idor_immediately(client, db_session, admin):
    for peer in ('127.0.0.1', '127.0.0.2', '127.0.0.3'):
        audit_verification(db_session, 'INTEGRITY_COMPROMISED', admin['user_id'], peer)
    append_audit(db_session, 'ACCESS_DENIED_IDOR', actor_id=admin['user_id'], target_type='DOCUMENT', status='DENIED')
    append_audit(db_session, 'ACCESS_DENIED_ROLE', actor_id=admin['user_id'], target_type='USER', status='DENIED')
    db_session.commit()
    result = client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()
    assert result['alert_total'] == 2
    assert {alert['code'] for alert in result['alerts']} == {'IDOR_ATTEMPT', 'REPEATED_VERIFICATION_FAILURE'}
    assert all(alert['actor_id'] == admin['user_id'] for alert in result['alerts'])


def test_alerts_expire_and_malformed_results_do_not_count_as_failures(client, db_session, admin):
    for _ in range(3):
        event = audit_verification(db_session, 'SIGNATURE_INVALID')
    event_id = event.id
    db_session.commit()
    db_session.execute(update(AuditLog).where(AuditLog.id == event_id).values(details_json='invalid-json'))
    db_session.commit()
    assert client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()['alert_total'] == 0
    db_session.execute(update(AuditLog).values(created_at=datetime.now(timezone.utc) - timedelta(minutes=16)))
    db_session.commit()
    assert client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()['alert_total'] == 0


def test_alert_response_is_bounded_and_reports_total(client, db_session, admin):
    for number in range(1, 23):
        append_audit(db_session, 'ACCESS_DENIED_IDOR', target_type='DOCUMENT', status='DENIED',
                     context=request_context(f'127.0.0.{number}'))
    db_session.commit()
    result = client.get('/api/v1/dashboard/stats', headers=admin['headers']).json()
    assert result['alert_total'] == 22 and len(result['alerts']) == 20


def test_stats_follow_real_signed_document_and_idor(client_p5, db_session, admin):
    private, _, pem, fingerprint = generate_test_rsa_3072()
    key = register_user_key(client_p5, admin, private, pem, fingerprint)
    doc_id, version_id, _, _, _ = create_and_sign_document(client_p5, admin, key, private)
    assert client_p5.get(f'/api/v1/documents/{doc_id}/versions/{version_id}/verify', headers=admin['headers']).status_code == 200
    other = register_and_login_user(client_p5, 'stats-other@cyber.edu')
    assert client_p5.get(f'/api/v1/documents/{doc_id}', headers=other['headers']).status_code == 404
    result = client_p5.get('/api/v1/dashboard/stats', headers=admin['headers']).json()
    assert result['total_documents'] == result['total_versions'] == result['signed_versions'] == 1
    assert result['verification_total'] == 1 and result['verification_success_rate'] == 100
    assert result['alerts'][0]['code'] == 'IDOR_ATTEMPT'
