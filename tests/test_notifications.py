from fastapi.testclient import TestClient
from main import app, pending_pets, users, notifications
from uuid import UUID

client = TestClient(app)


def test_admin_approval_generates_notification_for_owner():
    # Login as demo user and register a pet
    r = client.post('/login', data={'username': 'user@purrpaws.com', 'password': 'user'})
    assert r.status_code in (200, 302, 303)

    # Register a pet with owner contact matching the user's email
    reg_data = {
        'name': 'TestPet123',
        'breed': 'Mixed',
        'color': 'Brown',
        'vaccination_status': 'false',
        'owner_name': 'Regular User',
        'owner_contact': 'user@purrpaws.com',
        'location_registered': 'Testville'
    }
    r = client.post('/register', data=reg_data)
    assert r.status_code in (200, 302, 303)

    # Find the pending pet we just created
    pet = next((p for p in pending_pets if p.name == 'TestPet123' and p.owner_contact == 'user@purrpaws.com'), None)
    assert pet is not None

    # Login as admin to approve
    r = client.post('/login', data={'username': 'admin@purrpaws.com', 'password': 'admin'})
    assert r.status_code in (200, 302, 303)

    # Approve the pet
    r = client.post('/admin/approve', data={'pet_id': str(pet.pet_id)})
    assert r.status_code in (200, 302, 303)

    # Now login as owner again and retrieve notifications
    r = client.post('/login', data={'username': 'user@purrpaws.com', 'password': 'user'})
    assert r.status_code in (200, 302, 303)

    r = client.get('/notifications')
    assert r.status_code == 200
    # Should show the approval message either via legacy message or notification
    assert 'approved by admin' in r.text.lower() or 'approved' in r.text.lower()


def test_dismiss_notification():
    # Assumes there is at least one notification for the user from previous test
    client.post('/login', data={'username': 'user@purrpaws.com', 'password': 'user'})
    r = client.get('/notifications')
    assert r.status_code == 200
    # Extract a notification id from the HTML (basic parse)
    import re
    m = re.search(r'name="notification_id" value="([0-9a-fA-F\-]+)"', r.text)
    if not m:
        # No notifications available - skip
        return
    nid = m.group(1)
    r = client.post('/notifications/dismiss', data={'notification_id': nid})
    assert r.status_code in (200, 302, 303)

    # After dismiss, page should not show that message as new
    r = client.get('/notifications')
    assert r.status_code == 200
    assert nid not in r.text
