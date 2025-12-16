import sys
from pathlib import Path
# ensure project root is importable
sys.path.append(str(Path(__file__).resolve().parents[1]))

from main import app, save_state, load_state, exports, scheduled_exports, generate_exports, check_and_run_scheduled_exports, _maybe_start_scheduler, _stop_scheduler
from fastapi.testclient import TestClient
import os
import time

client = TestClient(app)


def login_admin(client: TestClient):
    # Use the seeded admin credentials from main.users
    res = client.post("/login", data={"username": "admin@purrpaws.com", "password": "admin"}, follow_redirects=True)
    assert res.status_code in (200, 302, 303)


def test_manual_run_scheduled_export(tmp_path):
    # ensure clean state
    load_state()
    # schedule a job that should run when triggered
    scheduled_exports.clear()
    scheduled_exports.append({
        "id": "test-sched-1",
        "frequency_minutes": 0,
        "last_run": None,
        "created_by": "admin@example.com",
    })
    save_state()

    login_admin(client)
    # call manual run endpoint
    res = client.post("/admin/exports/run", follow_redirects=False)
    assert res.status_code == 303
    # exports list should now have at least one export generated
    load_state()
    assert len(exports) >= 1


def test_scheduler_start_stop():
    # Ensure the scheduler start/stop functions run without error
    os.environ["ENABLE_SCHEDULER"] = "1"
    try:
        _maybe_start_scheduler()
        # give the thread a moment to start
        time.sleep(0.2)
        # thread should be set; check that calling stop works
        _stop_scheduler()
    finally:
        os.environ.pop("ENABLE_SCHEDULER", None)