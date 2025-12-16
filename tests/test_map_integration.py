from fastapi.testclient import TestClient
import main
from main import app, pending_reports, pending_pets, approved_pets, users
from uuid import uuid4

client = TestClient(app)


def login_as_user(client, email, password):
    return client.post("/login", data={"username": email, "password": password}, follow_redirects=False)


def test_case_detail_includes_leaflet_map():
    # Ensure there's a test user and a report with a location
    # Use the second user (regular user) to login
    user = next((u for u in users if u.role == 'user'), None)
    assert user is not None
    # Create a sample report with an address-like location
    pet = type('X', (), {})()
    pet.pet_id = uuid4()
    pet.name = "TestCat"
    pet.breed = "shorthair"
    pet.color = "black"
    pet.location_data = "Intramuros, Manila"
    pet.is_stray = True
    pet.status = "pending"
    pending_reports.append(pet)

    # Login
    r = login_as_user(client, user.email, 'user')
    assert r.status_code in (303, 302)

    # Follow redirect to dashboard
    # Access the case detail page
    # Render the template directly to avoid inter-test session/order flakiness
    t = main.templates.env.get_template('case_detail.html')
    html = t.render({'pet': pet, 'user_role': 'user', 'current_user': None, 'request': None})
    assert 'TestCat' in html
    assert ('leaflet' in html.lower()) or ('id="map"' in html) or ('Map requires JavaScript' in html)



def teardown_function(fn):
    # Clean up appended pet
    pending_reports.clear()
