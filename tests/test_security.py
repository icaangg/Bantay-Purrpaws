from fastapi.testclient import TestClient
from main import app, pending_pets
from uuid import uuid4

client = TestClient(app)


def test_admin_cannot_bypass_with_query_param():
    # Add a pending pet to try to approve
    pet = type('P', (), {})()
    pet.pet_id = uuid4()
    pet.name = "BypassTest"
    pet.breed = "none"
    pet.color = "none"
    pet.location_data = "Nowhere"
    pet.is_stray = False
    pet.status = "pending"
    pending_pets.append(pet)

    # Attempt to call admin approve endpoint without logging in but with query param
    r = client.post(f"/admin/approve?user_role=admin", data={"pet_id": str(pet.pet_id)}, follow_redirects=False)
    assert r.status_code in (302, 303)
    # Should redirect to login because session is required for admin role
    assert r.headers.get('location', '').startswith('/login')


def teardown_function(fn):
    pending_pets.clear()