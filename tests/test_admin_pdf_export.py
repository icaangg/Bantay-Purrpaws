from fastapi.testclient import TestClient
from main import app, approved_pets, users
from uuid import uuid4

client = TestClient(app)


def login_as_admin(client, email, password):
    return client.post("/login", data={"username": email, "password": password}, follow_redirects=False)


def test_admin_can_export_pdf():
    admin_user = next((u for u in users if u.role == 'admin'), None)
    assert admin_user is not None

    # Add a sample approved pet
    pet = type('P', (), {})()
    pet.pet_id = uuid4()
    pet.name = "PDFCat"
    pet.breed = "mixed"
    pet.color = "brown"
    pet.location_data = "Quezon City"
    pet.is_stray = False
    pet.status = "approved"
    approved_pets.append(pet)

    # Login as admin
    r = login_as_admin(client, admin_user.email, 'admin')
    assert r.status_code in (303, 302)

    r = client.get('/admin/export/pets.pdf')
    assert r.status_code == 200
    assert r.headers.get('content-type', '').startswith('application/pdf')
    # PDF files start with %PDF
    assert r.content.startswith(b'%PDF')


def teardown_function(fn):
    approved_pets.clear()
