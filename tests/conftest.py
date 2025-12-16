import sys
from pathlib import Path

# ensure project root is importable for tests
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest
import os


@pytest.fixture(autouse=True)
def isolate_state(tmp_path):
    """Isolate global in-memory state and export files for each test to avoid order-dependent flakiness."""
    import main

    # snapshot
    orig_exports = list(main.exports)
    orig_scheduled = list(main.scheduled_exports)
    orig_approved = list(main.approved_pets)
    orig_pending_pets = list(main.pending_pets)
    orig_pending_reports = list(main.pending_reports)
    orig_logs = list(main.logs)
    orig_login_attempts = dict(getattr(main, 'LOGIN_ATTEMPTS', {}))

    # clean runtime state and export dir
    main.exports.clear()
    main.scheduled_exports.clear()
    main.approved_pets.clear()
    main.pending_pets.clear()
    main.pending_reports.clear()
    main.logs.clear()
    main.LOGIN_ATTEMPTS.clear()

    export_dir = os.path.join('data', 'exports')
    if os.path.exists(export_dir):
        for f in os.listdir(export_dir):
            try:
                os.remove(os.path.join(export_dir, f))
            except Exception:
                pass

    yield

    # teardown: remove any files created by the test and restore state
    if os.path.exists(export_dir):
        for f in os.listdir(export_dir):
            try:
                os.remove(os.path.join(export_dir, f))
            except Exception:
                pass

    main.exports.clear()
    main.scheduled_exports.clear()
    main.approved_pets.clear()
    main.pending_pets.clear()
    main.pending_reports.clear()
    main.logs.clear()
    main.LOGIN_ATTEMPTS.clear()

    main.exports.extend(orig_exports)
    main.scheduled_exports.extend(orig_scheduled)
    main.approved_pets.extend(orig_approved)
    main.pending_pets.extend(orig_pending_pets)
    main.pending_reports.extend(orig_pending_reports)
    main.logs.extend(orig_logs)
    main.LOGIN_ATTEMPTS.update(orig_login_attempts)
