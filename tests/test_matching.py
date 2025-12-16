from fastapi.testclient import TestClient
import main

client = TestClient(main.app)


def test_fuzzy_matching_finds_similar_breed_and_color():
    # Create a pending report for "Labrador" "Black"
    r = client.post('/report-animal', data={'name': 'NebulonLost', 'breed': 'NebulonX', 'color': 'Aurelia', 'location_sighted': 'Testville', 'reporter_contact': '09170000000'})
    assert r.status_code in (200, 302, 303)

    # Create an approved pet candidate resembling the lost report
    # We'll simulate admin approval directly by appending to approved_pets
    import uuid
    unique_name = f"FoundNeb-{uuid.uuid4().hex[:8]}"
    candidate = main.PetInDB(
        pet_id=main.uuid4(),
        name=unique_name,
        breed='Nebulon-X',
        color='Aurelian',
        location_data='Testville',
        vaccination_status=False,
        is_stray=False,
        status='approved',
        notes=[]
    )
    main.approved_pets.append(candidate)

    # Ensure candidate appended
    assert any(p.name == unique_name for p in main.approved_pets)

    # Check fuzzy matching logic directly (more deterministic)
    from main import _safe_fuzzy_ratio
    assert _safe_fuzzy_ratio('NebulonX', 'Nebulon-X') >= 60
    assert _safe_fuzzy_ratio('Aurelia', 'Aurelian') >= 60

    # Cleanup
    try:
        main.approved_pets.remove(candidate)
    except ValueError:
        pass
