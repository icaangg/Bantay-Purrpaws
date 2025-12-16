from fastapi.testclient import TestClient
import time
import main

client = TestClient(main.app)


def test_session_expires_when_max_age_changed():
    # login
    r = client.post('/login', data={'username': 'user@purrpaws.com', 'password': 'user'})
    assert r.status_code in (200, 302, 303)

    # profile should be accessible immediately
    r2 = client.get('/profile')
    assert r2.status_code == 200

    # simulate expiry by reducing SESSION_MAX_AGE
    original = main.SESSION_MAX_AGE
    main.SESSION_MAX_AGE = 0

    try:
        r3 = client.get('/profile', follow_redirects=False)
        # Should redirect to login when session considered expired
        assert r3.status_code in (302, 303)
        assert '/login' in r3.headers.get('location', '')
    finally:
        # restore
        main.SESSION_MAX_AGE = original
