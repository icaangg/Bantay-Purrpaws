# Bantay PurrPaws (Demo)

This is a demo app for pet reporting and matching. It includes session-based authentication, per-user notifications, fuzzy matching, map integration, and admin exports (CSV/PDF).

## Quick Start

1. Create and activate a virtualenv and install requirements:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

2. Run the app:

```bash
uvicorn main:app --reload
```

3. Open http://127.0.0.1:8000 and login using the demo admin user `admin@purrpaws.com` / password `admin`.

## Exports & Scheduling

- Admins can generate on-demand exports at `/admin/exports` (Generate Export Now).
- Generated CSV and PDF files are stored in `data/exports/` and listed in the admin UI.
- You can schedule recurring exports using the Schedule form (frequency in minutes).
- A simple scheduler is available, but to avoid background threads in tests it is disabled by default.

To enable a production scheduler, set `ENABLE_SCHEDULER=1` in the environment before starting the app. The scheduler will check scheduled jobs and run them when due.

## CI

A GitHub Actions workflow is included at `.github/workflows/ci.yml` that installs dependencies and runs `pytest` on pushes and pull requests. Make sure to include any additional dependencies if you alter `requirements.txt`.

## Notes

- This project uses `data/state.json` to persist users, pets, notifications, and exports for demo purposes. For production use, replace with a proper database.
- Passwords are hashed using `passlib`.
- PDF exports rely on `reportlab` (included in `requirements.txt`).
