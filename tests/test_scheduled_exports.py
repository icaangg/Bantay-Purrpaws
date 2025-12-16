from fastapi.testclient import TestClient
from main import app, approved_pets, exports
from uuid import uuid4
import os

client = TestClient(app)


def login_as_admin(client, email, password):
    return client.post("/login", data={"username": email, "password": password}, follow_redirects=False)


def test_admin_can_generate_exports_and_download():
    admin_user = next((u for u in __import__('main').users if u.role == 'admin'), None)
    assert admin_user is not None

    # Add a sample approved pet (use PetInDB to ensure persistence functions work)
    from main import PetInDB
    pet = PetInDB(
        pet_id=uuid4(),
        name="SchedCat",
        breed="mixed",
        color="black",
        location_data="Manila",
        vaccination_status=False,
        is_stray=False,
        photo_url=None,
        owner_user_id=None,
        reporter_user_id=None,
        owner_name=None,
        owner_contact=None,
        reporter_contact=None,
        status="approved",
        is_found=False,
        notes=[],
        date_reported=None,
        description=None,
    )
    approved_pets.append(pet)

    r = login_as_admin(client, admin_user.email, 'admin')
    assert r.status_code in (302, 303)

    # Trigger generation via GET convenience endpoint
    r = client.get('/admin/exports/generate')
    assert r.status_code in (200, 302, 303)

    # Check that an export was created and try to download CSV
    assert len(exports) > 0
    last_export = exports[-1]
    csv_path = last_export.get('csv')

    # Try downloading first (this will succeed even if the file check race occurs)
    r = client.get(f"/admin/exports/download/{last_export.get('export_id')}/csv")
    if r.status_code == 200 and 'SchedCat' in r.text:
        # Good enough - downloadable and contains our pet
        pass
    else:
        # Fall back to checking file existence with retries
        import time
        found = False
        for _ in range(20):
            if csv_path and os.path.exists(csv_path):
                found = True
                break
            time.sleep(0.1)
        assert csv_path and found

    r = client.get(f"/admin/exports/download/{last_export.get('export_id')}/csv")
    assert r.status_code == 200
    assert 'SchedCat' in r.text


def test_schedule_and_unschedule_endpoints():
    admin_user = next((u for u in __import__('main').users if u.role == 'admin'), None)
    assert admin_user is not None
    r = login_as_admin(client, admin_user.email, 'admin')
    assert r.status_code in (302, 303)

    # Schedule a job using endpoint
    r = client.post('/admin/exports/schedule', data={'frequency_minutes': '0', 'start_immediately': '0'}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert len(__import__('main').scheduled_exports) > 0
    job_id = __import__('main').scheduled_exports[-1]['job_id']

    # Unschedule it
    r = client.post('/admin/exports/unschedule', data={'job_id': job_id}, follow_redirects=False)
    assert r.status_code in (302, 303)
    assert all(j['job_id'] != job_id for j in __import__('main').scheduled_exports)


def teardown_function(fn):
    # Clean up exports and files
    for e in list(exports):
        csv = e.get('csv')
        pdf = e.get('pdf')
        if csv and os.path.exists(csv):
            os.remove(csv)
        if pdf and os.path.exists(pdf):
            os.remove(pdf)
    exports.clear()
    approved_pets.clear()
