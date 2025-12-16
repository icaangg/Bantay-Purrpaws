from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_login_and_session_persists():
    # Ensure login page loads
    r = client.get("/login")
    assert r.status_code == 200

    # Login with demo user
    r = client.post("/login", data={"username": "user@purrpaws.com", "password": "user"})
    # Expect redirect to home or dashboard
    assert r.status_code in (200, 302, 303)

    # After login, profile should be accessible and show user's email
    r = client.get("/profile")
    assert r.status_code == 200
    assert "user@purrpaws.com" in r.text

    # Logout clears session
    r = client.get("/logout")
    assert r.status_code in (200, 302, 303)

    # After logout, profile should require login (redirect)
    r = client.get("/profile", follow_redirects=False)
    assert r.status_code in (302, 303)
    assert "/login" in r.headers.get("location", "")
