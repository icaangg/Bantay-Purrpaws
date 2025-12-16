from fastapi.testclient import TestClient
from main import app, pending_pets, pending_reports, approved_pets, users
from uuid import uuid4

client = TestClient(app)


def login_as_admin(client, email, password):
    return client.post("/login", data={"username": email, "password": password}, follow_redirects=False)


def test_admin_can_export_csv():
    admin_user = next((u for u in users if u.role == 'admin'), None)
    assert admin_user is not None

    # Add a sample approved pet
    pet = type('P', (), {})()
    pet.pet_id = uuid4()
    pet.name = "ExportCat"
    pet.breed = "mixed"
    pet.color = "brown"
    pet.location_data = "Quezon City"
    pet.is_stray = False
    pet.status = "approved"
    approved_pets.append(pet)

    # Login as admin
    r = login_as_admin(client, admin_user.email, 'admin')
    assert r.status_code in (303, 302)

    # Get CSV
    r = client.get('/admin/export/pets.csv')
    assert r.status_code == 200
    assert r.headers.get('content-type', '').startswith('text/csv')
    assert 'ExportCat' in r.text


def test_admin_dashboard_has_export_link():
    admin_user = next((u for u in users if u.role == 'admin'), None)
    assert admin_user is not None
    r = login_as_admin(client, admin_user.email, 'admin')
    assert r.status_code in (303, 302)
    r = client.get('/admin/dashboard')
    assert r.status_code == 200
    assert '/admin/export/pets.csv' in r.text


def teardown_function(fn):
    approved_pets.clear()
