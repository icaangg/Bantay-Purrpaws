import os
import shutil
import json
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Form, UploadFile, File
import io
import csv
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from pydantic import BaseModel
from uuid import UUID, uuid4 
from typing import List, Optional
from starlette.status import HTTP_303_SEE_OTHER
from fastapi.staticfiles import StaticFiles
import threading
from difflib import SequenceMatcher


def _safe_fuzzy_ratio(a: str, b: str) -> int:
    """Return a fuzzy match score between 0-100. Prefer rapidfuzz if available, else fallback."""
    try:
        from rapidfuzz import fuzz
        return int(fuzz.token_sort_ratio(a, b))
    except Exception:
        if not a or not b:
            return 0
        s = SequenceMatcher(None, a, b)
        return int(round(s.ratio() * 100))

# Scheduler control
_scheduler_thread = None
_scheduler_stop_event = threading.Event()

# --- File Upload Configuration (New) ---
UPLOAD_DIR = "static/uploads"
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Exports dir
EXPORT_DIR = os.path.join("data", "exports")
def _ensure_export_dir():
    os.makedirs(EXPORT_DIR, exist_ok=True)

# --- User Schemas ---
class User(BaseModel):
    full_name: str  # Kept for backward compatibility, can be constructed from first/middle/last
    email: str # Used as username
    password: str # In a real app, this would be hashed
    role: str # 'user' or 'admin'
    birthday: Optional[str] = None
    address: Optional[str] = None
    contact_info: Optional[str] = None
    notifications_enabled: bool = True
    privacy_public: bool = True
    # New fields for enhanced registration
    first_name: Optional[str] = None
    middle_name: Optional[str] = None
    last_name: Optional[str] = None
    gender: Optional[str] = None
    profile_photo_url: Optional[str] = None
    mobile_number: Optional[str] = None

class UserAccount(User):
    user_id: UUID

# --- Pet Schemas ---
# Schema for REPORTING a Stray/Lost Animal (Basic details + location/reporter contact)
class ReportAnimalData(BaseModel):
    name: str
    breed: str
    color: str
    location_sighted: str 
    reporter_contact: str
    is_stray: bool = True
    vaccination_status: bool = False # Assume unknown/false for strays
    photo_filename: Optional[str] = None # Added for stored filename

# Schema for REGISTERING an Owned Pet (Detailed info + location/owner contact)
class OwnedPetData(BaseModel):
    name: str
    breed: str
    color: str
    owner_name: str # New field for owner's name
    owner_contact: str # New field for owner's contact
    location_registered: str
    vaccination_status: bool
    is_stray: bool = False
    photo_filename: Optional[str] = None # Added for stored filename


# Schema for internal database storage (combines all pet fields)
class PetInDB(BaseModel):
    pet_id: UUID
    name: str
    breed: str
    color: str
    location_data: str # Can be location_registered or location_sighted
    vaccination_status: bool
    is_stray: bool
    photo_url: Optional[str] = None
    # Link to registered users where applicable
    owner_user_id: Optional[UUID] = None
    reporter_user_id: Optional[UUID] = None
    # For owned pets:
    owner_name: Optional[str] = None
    owner_contact: Optional[str] = None
    # For stray reports:
    reporter_contact: Optional[str] = None
    status: str = "pending"
    is_found: bool = False
    notes: List[str] = []
    # Optional additional fields
    date_reported: Optional[str] = None
    description: Optional[str] = None

# --- App Setup ---
app = FastAPI()

# Add session middleware for simple session-based auth
SESSION_SECRET = os.environ.get("SESSION_SECRET", "dev-secret-please-change")
SESSION_MAX_AGE = int(os.environ.get("SESSION_MAX_AGE", "3600"))  # seconds
SESSION_HTTPS_ONLY = bool(int(os.environ.get("SESSION_HTTPS_ONLY", "0")))
SESSION_SAME_SITE = os.environ.get("SESSION_SAME_SITE", "lax")
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=SESSION_MAX_AGE,
    same_site=SESSION_SAME_SITE,
    https_only=SESSION_HTTPS_ONLY,
)

# Password hasher
# Use pbkdf2_sha256 as the primary scheme to avoid bcrypt's 72-byte limit, but
# keep bcrypt for existing hashes.
pwd_context = CryptContext(
    schemes=["pbkdf2_sha256", "bcrypt"],
    deprecated="auto",
)

# Simple in-memory rate limiter for auth endpoints (per-IP)
LOGIN_ATTEMPTS = {}
LOGIN_WINDOW = int(os.environ.get("LOGIN_WINDOW", "300"))  # seconds
LOGIN_MAX_ATTEMPTS = int(os.environ.get("LOGIN_MAX_ATTEMPTS", "5"))

# Mount static files (including uploads)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


# --- Data Structures (In-memory storage for demonstration) ---
# 1. User Accounts (Simulated Database)
users: List[UserAccount] = [
    UserAccount(
        user_id=uuid4(),
        full_name="Admin User",
        email="admin@purrpaws.com",
        password="admin", # Insecure password for demo
        role="admin",
        birthday=None,
        address=None,
        contact_info=None,
        notifications_enabled=True,
        privacy_public=True
    ),
    UserAccount(
        user_id=uuid4(),
        full_name="Regular User",
        email="user@purrpaws.com",
        password="user", # Insecure password for demo
        role="user",
        birthday=None,
        address=None,
        contact_info=None,
        notifications_enabled=True,
        privacy_public=True
    )
]

# 2. Pending Stray Reports (Initial state)
pending_reports: List[PetInDB] = []

# 3. Pending Pet Registrations (Initial state)
pending_pets: List[PetInDB] = []

# 4. Approved Pets (Now starting empty)
approved_pets: List[PetInDB] = [] # UPDATED: Starting empty as requested
logs: List[str] = []

# --- Notifications (per-user persistent notifications) ---
class Notification(BaseModel):
    notification_id: UUID
    user_id: Optional[UUID] = None
    message: str
    read: bool = False
    timestamp: Optional[str] = None

notifications: List[Notification] = []

# --- Announcements (admin-created announcements) ---
class Announcement(BaseModel):
    announcement_id: UUID
    title: str
    content: str
    created_by: Optional[UUID] = None
    created_at: str
    published: bool = True

announcements_list: List[Announcement] = []

# --- Community Stories/Reviews (user feedback) ---
class CommunityStory(BaseModel):
    story_id: UUID
    user_id: Optional[UUID] = None
    user_name: str
    rating: int  # 1-5 stars
    feedback: str
    created_at: str

community_stories: List[CommunityStory] = []

# --- Approved Registration History ---
approved_registration_history: List[PetInDB] = []

# --- Export records & scheduling ---
# Persisted export records (generated files metadata)
exports: List[dict] = []
# Scheduled export jobs
scheduled_exports: List[dict] = []

# --- Persistence (simple JSON for demo) ---
STATE_FILE = os.path.join("data", "state.json")

def _ensure_state_dir():
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)

def _pet_to_dict(p: PetInDB) -> dict:
    return {
        "pet_id": str(p.pet_id),
        "name": p.name,
        "breed": p.breed,
        "color": p.color,
        "location_data": p.location_data,
        "vaccination_status": p.vaccination_status,
        "is_stray": p.is_stray,
        "photo_url": p.photo_url,
        "owner_name": p.owner_name,
        "owner_contact": p.owner_contact,
        "owner_user_id": str(p.owner_user_id) if p.owner_user_id else None,
        "reporter_user_id": str(p.reporter_user_id) if p.reporter_user_id else None,
        "reporter_contact": p.reporter_contact,
        "status": p.status,
        "is_found": p.is_found,
        "notes": p.notes,
        "date_reported": p.date_reported,
        "description": p.description,
    }

def _pet_from_dict(d: dict) -> PetInDB:
    return PetInDB(
        pet_id=UUID(d["pet_id"]),
        name=d["name"],
        breed=d["breed"],
        color=d["color"],
        location_data=d["location_data"],
        vaccination_status=d["vaccination_status"],
        is_stray=d["is_stray"],
        photo_url=d.get("photo_url"),
        owner_name=d.get("owner_name"),
        owner_contact=d.get("owner_contact"),
        owner_user_id=UUID(d["owner_user_id"]) if d.get("owner_user_id") else None,
        reporter_user_id=UUID(d["reporter_user_id"]) if d.get("reporter_user_id") else None,
        reporter_contact=d.get("reporter_contact"),
        status=d.get("status", "pending"),
        is_found=d.get("is_found", False),
        notes=d.get("notes", []),
        date_reported=d.get("date_reported"),
        description=d.get("description"),
    )

def _user_to_dict(u: UserAccount) -> dict:
    return {
        "user_id": str(u.user_id),
        "full_name": u.full_name,
        "email": u.email,
        "password": u.password,
        "role": u.role,
        "birthday": u.birthday,
        "address": u.address,
        "contact_info": u.contact_info,
        "notifications_enabled": u.notifications_enabled,
        "privacy_public": u.privacy_public,
        "first_name": getattr(u, 'first_name', None),
        "middle_name": getattr(u, 'middle_name', None),
        "last_name": getattr(u, 'last_name', None),
        "gender": getattr(u, 'gender', None),
        "profile_photo_url": getattr(u, 'profile_photo_url', None),
        "mobile_number": getattr(u, 'mobile_number', None),
    }

def _user_from_dict(d: dict) -> UserAccount:
    return UserAccount(
        user_id=UUID(d["user_id"]),
        full_name=d["full_name"],
        email=d["email"],
        password=d["password"],
        role=d["role"],
        birthday=d.get("birthday"),
        address=d.get("address"),
        contact_info=d.get("contact_info"),
        notifications_enabled=d.get("notifications_enabled", True),
        privacy_public=d.get("privacy_public", True),
        first_name=d.get("first_name"),
        middle_name=d.get("middle_name"),
        last_name=d.get("last_name"),
        gender=d.get("gender"),
        profile_photo_url=d.get("profile_photo_url"),
        mobile_number=d.get("mobile_number"),
    )


def _notification_to_dict(n: Notification) -> dict:
    return {
        "notification_id": str(n.notification_id),
        "user_id": str(n.user_id) if n.user_id else None,
        "message": n.message,
        "read": n.read,
        "timestamp": n.timestamp,
    }


def _notification_from_dict(d: dict) -> Notification:
    return Notification(
        notification_id=UUID(d["notification_id"]),
        user_id=UUID(d["user_id"]) if d.get("user_id") else None,
        message=d.get("message", ""),
        read=d.get("read", False),
        timestamp=d.get("timestamp"),
    )


def _announcement_to_dict(a: Announcement) -> dict:
    return {
        "announcement_id": str(a.announcement_id),
        "title": a.title,
        "content": a.content,
        "created_by": str(a.created_by) if a.created_by else None,
        "created_at": a.created_at,
        "published": a.published,
    }


def _announcement_from_dict(d: dict) -> Announcement:
    return Announcement(
        announcement_id=UUID(d["announcement_id"]),
        title=d["title"],
        content=d["content"],
        created_by=UUID(d["created_by"]) if d.get("created_by") else None,
        created_at=d["created_at"],
        published=d.get("published", True),
    )


def _story_to_dict(s: CommunityStory) -> dict:
    return {
        "story_id": str(s.story_id),
        "user_id": str(s.user_id) if s.user_id else None,
        "user_name": s.user_name,
        "rating": s.rating,
        "feedback": s.feedback,
        "created_at": s.created_at,
    }


def _story_from_dict(d: dict) -> CommunityStory:
    return CommunityStory(
        story_id=UUID(d["story_id"]),
        user_id=UUID(d["user_id"]) if d.get("user_id") else None,
        user_name=d["user_name"],
        rating=d["rating"],
        feedback=d["feedback"],
        created_at=d["created_at"],
    )


def _export_from_dict(d: dict) -> dict:
    return {
        "export_id": d.get("export_id"),
        "timestamp": d.get("timestamp"),
        "csv": d.get("csv"),
        "pdf": d.get("pdf"),
        "created_by": d.get("created_by"),
    }


def save_state():
    _ensure_state_dir()
    data = {
        "users": [_user_to_dict(u) for u in users],
        "pending_reports": [_pet_to_dict(p) for p in pending_reports],
        "pending_pets": [_pet_to_dict(p) for p in pending_pets],
        "approved_pets": [_pet_to_dict(p) for p in approved_pets],
        "approved_registration_history": [_pet_to_dict(p) for p in approved_registration_history],
        "logs": logs[-200:],  # keep last 200 entries
        "notifications": [_notification_to_dict(n) for n in notifications],
        "announcements": [_announcement_to_dict(a) for a in announcements_list],
        "community_stories": [_story_to_dict(s) for s in community_stories],
        "exports": [e for e in exports],
        "scheduled_exports": [s for s in scheduled_exports],
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def load_state():
    global users, pending_reports, pending_pets, approved_pets, logs, notifications
    global announcements_list, community_stories, approved_registration_history
    if not os.path.exists(STATE_FILE):
        return
    with open(STATE_FILE, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except Exception:
            # If the state file is empty or invalid, treat as no state
            return
    users = [_user_from_dict(u) for u in data.get("users", [])] or users
    pending_reports.clear()
    pending_reports.extend([_pet_from_dict(p) for p in data.get("pending_reports", [])])
    pending_pets.clear()
    pending_pets.extend([_pet_from_dict(p) for p in data.get("pending_pets", [])])
    approved_pets.clear()
    approved_pets.extend([_pet_from_dict(p) for p in data.get("approved_pets", [])])
    approved_registration_history.clear()
    approved_registration_history.extend([_pet_from_dict(p) for p in data.get("approved_registration_history", [])])
    logs = data.get("logs", [])
    notifications.clear()
    notifications.extend([_notification_from_dict(n) for n in data.get("notifications", [])])
    announcements_list = [_announcement_from_dict(a) for a in data.get("announcements", [])]
    community_stories = [_story_from_dict(s) for s in data.get("community_stories", [])]
    # Load persisted exports and scheduled jobs if present
    global exports, scheduled_exports
    # preserve existing list objects to avoid breaking references held by tests
    exports.clear()
    exports.extend([ _export_from_dict(e) for e in data.get("exports", []) ])
    scheduled_exports.clear()
    scheduled_exports.extend(data.get("scheduled_exports", []))


load_state()

# Ensure users' passwords are hashed (bcrypt when possible, pbkdf2_sha256 for long values)
from passlib.hash import pbkdf2_sha256
for u in users:
    pw = u.password or ""
    if not pw.startswith("$2") and not pw.startswith("$pbkdf2-sha256$"):
        try:
            if len(pw.encode('utf-8')) > 72:
                u.password = pbkdf2_sha256.hash(pw)
            else:
                u.password = pwd_context.hash(pw)
        except Exception:
            u.password = pbkdf2_sha256.hash(pw)

# --- Utility Function ---
def get_user_role(request: Request) -> str:
    """A placeholder for real authentication logic. Reads role from URL query param."""
    # Prefer session-based user if present
    user_id = request.session.get("user_id")
    if user_id:
        # find the matching user
        u = next((x for x in users if str(x.user_id) == str(user_id)), None)
        if u:
            return u.role
    # No longer fall back to query param - session-only role
    return "guest"


def get_current_user(request: Request) -> Optional[UserAccount]:
    """Return the authenticated UserAccount if any (based on session), otherwise None.

    Implements a simple session timeout: if the session's `last_active` timestamp
    exceeds `SESSION_MAX_AGE`, the session is cleared and the user must log in again.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return None

    last_active = request.session.get("last_active")
    if last_active:
        try:
            la = datetime.fromisoformat(last_active)
            # Ensure timezone awareness for comparison
            if la.tzinfo is None:
                la = la.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - la).total_seconds()
            if age > SESSION_MAX_AGE:
                # session expired
                request.session.clear()
                return None
        except Exception:
            # If parsing fails, clear session to be safe
            request.session.clear()
            return None

    # Update last_active (sliding expiration)
    request.session["last_active"] = datetime.now(timezone.utc).isoformat()

    return next((x for x in users if str(x.user_id) == str(user_id)), None)


def resolve_user(request: Request):
    """Return tuple (user_role, current_user) where current_user is the session user if present.

    Note: this helper no longer falls back to a role-based demo user. Endpoints that require
    an authenticated user should check `current_user` and redirect to login if None. For
    legacy UI fallbacks (e.g., demo links) use `get_user_role(request)` directly when needed.
    """
    user_role = get_user_role(request)
    current_user = get_current_user(request)
    return user_role, current_user

def save_upload_file(upload_file: UploadFile) -> Optional[str]:
    """Saves the uploaded file to the UPLOAD_DIR and returns the filename."""
    if not upload_file or not getattr(upload_file, 'filename', None):
        return None

    # Sanitize filename (basic example) and create a unique path
    file_extension = os.path.splitext(upload_file.filename)[1]
    unique_filename = f"{uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    # Save the file content
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
        return f"/static/uploads/{unique_filename}"
    except Exception:
        # Handle save error, but for demo just return None
        return None

# --- 1. Core Pages & Static Endpoints ---

@app.get("/", tags=["Core Pages"])
def read_root(request: Request):
    """Renders the home page."""
    user_role, current_user = resolve_user(request)

    # user-facing lists (demo: not filtered by owner)
    my_pets = [p for p in approved_pets + pending_pets if not p.is_stray][:5]
    my_reports = [p for p in pending_reports + approved_pets if p.is_stray][:5]

    # Homepage stats and previews
    stats = {
        "total_registered": len(pending_pets) + len(approved_pets),
        "verified": len([p for p in approved_pets if p.status in ("approved", "resolved")]),
        "reported_lost": len([p for p in pending_reports if p.is_stray and not p.is_found]),
        "reported_found": len([p for p in pending_reports if p.is_found]) + len([p for p in approved_pets if p.is_found]),
        "active_users": len(users),
    }

    recent_lost = sorted([p for p in pending_reports if p.is_stray and not p.is_found], key=lambda x: x.date_reported or "", reverse=True)[:4]
    recent_found = sorted([p for p in pending_reports if p.is_found], key=lambda x: x.date_reported or "", reverse=True)[:4]

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "my_pets": my_pets,
        "my_reports": my_reports,
        "stats": stats,
        "recent_lost": recent_lost,
        "recent_found": recent_found,
    }
    return templates.TemplateResponse("home.html", context)


@app.post("/notifications/dismiss", status_code=HTTP_303_SEE_OTHER, tags=["Core Pages"])
def dismiss_notification(request: Request, notification_id: str = Form(...)):
    user_role, current_user = resolve_user(request)
    if not current_user:
           return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    found = next((n for n in notifications if str(n.notification_id) == notification_id and n.user_id and str(n.user_id) == str(current_user.user_id)), None)
    if found:
        # mark as read
        found.read = True
        logs.append(f"User {current_user.email} dismissed notification {found.notification_id}.")
        save_state()

    return RedirectResponse(url="/notifications", status_code=HTTP_303_SEE_OTHER)


def add_notification(user_id: Optional[UUID], message: str):
    n = Notification(notification_id=uuid4(), user_id=user_id, message=message, read=False, timestamp=datetime.now(timezone.utc).isoformat())
    notifications.append(n)
    logs.append(f"Notification added for user {user_id}: {message}")
    save_state()


@app.get("/notifications", tags=["Core Pages"])
def read_notifications(request: Request):
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    # Show all notifications for the user (both read and unread)
    global notifications
    user_notifications = [n for n in notifications if n.user_id and str(n.user_id) == str(current_user.user_id)]
    
    # Sort notifications: unread first, then by timestamp (newest first)
    def sort_key(n: Notification):
        # Unread notifications come first (False sorts before True)
        read_priority = 0 if not n.read else 1
        # Parse timestamp for sorting (newest first)
        try:
            if n.timestamp:
                ts = datetime.fromisoformat(n.timestamp.replace('Z', '+00:00'))
                timestamp_value = ts.timestamp()
            else:
                timestamp_value = 0
        except:
            timestamp_value = 0
        return (read_priority, -timestamp_value)  # Negative for descending order
    
    user_notifications.sort(key=sort_key)

    # Get published announcements
    announcements = [a.content for a in announcements_list if a.published]
    responses = []

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "notifications": user_notifications,
        "announcements": announcements,
        "responses": responses
    }
    return templates.TemplateResponse("notifications.html", context) 


@app.get("/announcements", tags=["Core Pages"])
def read_announcements(request: Request):
    user_role, current_user = resolve_user(request)
    # Show only published announcements
    published_announcements = [a for a in announcements_list if a.published]
    items = [a.title + ": " + a.content for a in published_announcements]
    context = {"request": request, "user_role": user_role, "current_user": current_user, "items": items}
    return templates.TemplateResponse(request, "announcements.html", context) 


@app.get("/support", tags=["Core Pages"])
def read_support(request: Request):
    user_role, current_user = resolve_user(request)

    status = request.query_params.get("status")
    faq = [
        ("How to report a lost pet?", "Go to Report Animal and fill in details with a clear photo."),
        ("How to register my pet?", "Use Register Pet and include vaccination status if known."),
        ("How to update my profile?", "Use the Edit Profile link in the navbar dropdown.")
    ]
    context = {"request": request, "user_role": user_role, "current_user": current_user, "status": status, "faq": faq}
    return templates.TemplateResponse("support.html", context) 


@app.post("/support", status_code=HTTP_303_SEE_OTHER, tags=["Core Pages"])
def submit_support(request: Request, subject: str = Form(...), message: str = Form(...)):
    return RedirectResponse(
        url=f"/support?status=submitted",
        status_code=HTTP_303_SEE_OTHER
    )


@app.get("/settings", tags=["Core Pages"])
def read_settings(request: Request):
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    context = {"request": request, "user_role": user_role, "current_user": current_user}
    return templates.TemplateResponse(request, "settings.html", context) 


@app.post("/settings", status_code=HTTP_303_SEE_OTHER, tags=["Core Pages"])
def update_settings(
    request: Request,
    password: Optional[str] = Form(None),
    notifications_enabled: bool = Form(False),
    privacy_public: bool = Form(False)
):
    role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    if password:
        current_user.password = password
    current_user.notifications_enabled = notifications_enabled
    current_user.privacy_public = privacy_public
    save_state()

    return RedirectResponse(
        url=f"/settings?status=updated",
        status_code=HTTP_303_SEE_OTHER
    )


@app.get("/profile", tags=["Core Pages"])
def read_profile_page(request: Request):
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    context = {"request": request, "user_role": user_role, "current_user": current_user}
    return templates.TemplateResponse("profile.html", context) 


@app.post("/profile", tags=["Core Pages"])
def update_profile(
    request: Request,
    full_name: str = Form(...),
    birthday: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    contact_info: Optional[str] = Form(None),
):
    role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    current_user.full_name = full_name
    current_user.birthday = birthday
    current_user.address = address
    current_user.contact_info = contact_info
    save_state()

    return RedirectResponse(
        url=f"/",
        status_code=HTTP_303_SEE_OTHER
    )

# --- 2. Pet Registration Endpoints ---

@app.get("/register", tags=["Pet Management"])
def read_register_pet_page(request: Request):
    """Renders the owned pet registration page."""
    user_role, current_user = resolve_user(request)
    
    status = request.query_params.get('status') # UPDATED: Get status parameter
    
    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "status": status # UPDATED: Pass status to template
    }
    return templates.TemplateResponse(name="pet_register.html", context=context)


@app.post("/register", status_code=HTTP_303_SEE_OTHER, tags=["Pet Management"])
def process_register_pet(
    request: Request,
    name: str = Form(...),
    breed: str = Form(...),
    color: str = Form(...),
    species: Optional[str] = Form(None),  # Accept but not stored yet
    vaccination_status: bool = Form(False, alias="vaccination_status"),
    owner_name: str = Form(...),
    owner_contact: str = Form(...),
    location_registered: str = Form(...),
    photo_file: UploadFile = File(None),
):
    """Handles owned pet registration form submission and adds it to the pending queue."""
    # 1. Handle file upload (if any)
    photo_filename = save_upload_file(photo_file)
    # Attempt to associate the owner to the current session user if available
    _, current_user = resolve_user(request)
    owner_user_id = current_user.user_id if current_user else None
    
    # 2. Create the new PetInDB object
    new_pet = PetInDB(
        pet_id=uuid4(),
        name=name,
        breed=breed,
        color=color,
        location_data=location_registered,
        vaccination_status=vaccination_status,
        is_stray=False,
        photo_url=photo_filename,
        owner_name=owner_name,
        owner_contact=owner_contact,
        owner_user_id=owner_user_id,
        status="pending",
        notes=[],
    )

    # 3. Add pet to pending review queue
    pending_pets.append(new_pet)
    save_state()
    logs.append(f"Registered pet '{name}' (owner: {owner_name}) pending review.")
    save_state()

    # 4. Redirect the user back to the register page with a success status
    return RedirectResponse(url=f"/register?status=registered", status_code=HTTP_303_SEE_OTHER)

# --- 3. Report Animal Endpoints ---

@app.get("/report-animal", tags=["Pet Management"])
def read_report_animal_page(request: Request):
    """Renders the animal reporting page."""
    user_role, current_user = resolve_user(request)
    status = request.query_params.get('status') # Added to read status
    context = {"request": request, "user_role": user_role, "current_user": current_user, "status": status}
    return templates.TemplateResponse(name="report_animal.html", context=context)

@app.post("/report-animal", status_code=HTTP_303_SEE_OTHER, tags=["Pet Management"])
def process_report_animal(
    request: Request,
    name: str = Form(...),
    breed: str = Form(...),
    color: str = Form(...),
    species: Optional[str] = Form(None),  # Accept but not stored yet
    report_type: str = Form("lost"),
    location_sighted: str = Form(...),
    reporter_contact: str = Form(...),
    date_last_seen: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    photo_file: UploadFile = File(None)
):
    """Handles stray/lost animal report submission and adds it to the pending reports queue."""
    user_role = get_user_role(request)
    
    import traceback
    try:
        # 1. Handle file upload (if any)
        photo_filename = save_upload_file(photo_file)
        # Attempt to associate reporter to the current session user if available
        _, current_user = resolve_user(request)
        reporter_user_id = current_user.user_id if current_user else None

        # 2. Create the new PetInDB object
        new_report = PetInDB(
            pet_id=uuid4(),
            name=name,
            breed=breed,
            color=color,
            location_data=location_sighted,
            vaccination_status=False, # Default to false for strays
            is_stray=True,
            # mark as found if user reported a found animal
            is_found=True if report_type == "found" else False,
            photo_url=photo_filename,
            reporter_contact=reporter_contact,
            reporter_user_id=reporter_user_id,
            status="pending",
            notes=[],
            date_reported=date_last_seen,
            description=description,
        )

        # 3. Add report to pending reports queue
        pending_reports.append(new_report)
        save_state()
        logs.append(f"Reported animal '{name}' at {location_sighted} pending review.")
        save_state()

        # 4. Redirect the user back to the report page with a success status
        return RedirectResponse(url=f"/report-animal?status=reported", status_code=HTTP_303_SEE_OTHER)
    except Exception as e:
        tb = traceback.format_exc()
        logs.append(f"Error processing report: {e}\n{tb}")
        save_state()
        return RedirectResponse(url=f"/report-animal?status=error", status_code=HTTP_303_SEE_OTHER)

# --- 4. View All Pets Endpoint ---

@app.get("/view-all-pets", tags=["Core Pages"])
def read_view_pets_page(request: Request):
    """Renders the page showing all approved owned pets (registered pets, not stray reports)."""
    user_role, current_user = resolve_user(request)
    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()
    search_performed = any([filter_breed, filter_color, filter_location])

    def matches(p: PetInDB) -> bool:
        return (filter_breed in p.breed.lower()) and (filter_color in p.color.lower()) and (filter_location in p.location_data.lower())

    # Only show owned pets (registered pets), not stray reports
    owned_pets = [p for p in approved_pets if not p.is_stray]
    filtered = [p for p in owned_pets if matches(p)] if search_performed else []
    context = {
        "request": request,
        "pets": filtered,  # template expects 'pets'
        "user_role": user_role,
        "current_user": current_user,
        "search_performed": search_performed,
        "filters": {
            "breed": request.query_params.get("breed", ""),
            "color": request.query_params.get("color", ""),
            "location": request.query_params.get("location", "")
        }
    }
    return templates.TemplateResponse( "view_pets.html", context) 


@app.post("/adopt-request", status_code=HTTP_303_SEE_OTHER, tags=["Core Pages"])
def process_adopt_request(request: Request, pet_id: str = Form(...)):
    """Handles adoption requests and sends notification to pet owner."""
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required to request adoption.", status_code=HTTP_303_SEE_OTHER)
    
    global notifications
    try:
        pet_uuid = UUID(pet_id)
        # Find the pet in approved pets
        pet = next((p for p in approved_pets if p.pet_id == pet_uuid), None)
        
        if not pet:
            return RedirectResponse(url="/view-all-pets?error=Pet not found", status_code=HTTP_303_SEE_OTHER)
        
        # Check if pet has an owner user_id
        if not pet.owner_user_id:
            return RedirectResponse(url="/view-all-pets?error=Pet owner information not available", status_code=HTTP_303_SEE_OTHER)
        
        # Don't allow self-adoption
        if str(pet.owner_user_id) == str(current_user.user_id):
            return RedirectResponse(url="/view-all-pets?error=Cannot request adoption of your own pet", status_code=HTTP_303_SEE_OTHER)
        
        # Create notification for the pet owner
        from datetime import datetime, timezone
        adoption_notification = Notification(
            notification_id=uuid4(),
            user_id=pet.owner_user_id,
            message=f"{current_user.full_name} ({current_user.email}) is interested in adopting {pet.name}. Please contact them at {current_user.contact_info or current_user.mobile_number or current_user.email}.",
            read=False,
            timestamp=datetime.now(timezone.utc).isoformat()
        )
        notifications.append(adoption_notification)
        save_state()
        
        logs.append(f"Adoption request for '{pet.name}' from {current_user.full_name} to owner {pet.owner_user_id}")
        save_state()
        
        return RedirectResponse(url="/view-all-pets?status=adoption_requested", status_code=HTTP_303_SEE_OTHER)
    except ValueError:
        return RedirectResponse(url="/view-all-pets?error=Invalid pet ID", status_code=HTTP_303_SEE_OTHER)
    except Exception as e:
        logs.append(f"Error processing adoption request: {e}")
        save_state()
        return RedirectResponse(url="/view-all-pets?error=Error processing request", status_code=HTTP_303_SEE_OTHER)


@app.get("/lost", tags=["Core Pages"])
def read_lost_pets_page(request: Request):
    """List approved lost-pet reports."""
    user_role, current_user = resolve_user(request)
    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()
    search_performed = any([filter_breed, filter_color, filter_location])

    def matches(p: PetInDB) -> bool:
        return (
            filter_breed in (p.breed or "").lower()
            and filter_color in (p.color or "").lower()
            and filter_location in (p.location_data or "").lower()
        )

    pets = (
        [p for p in approved_pets if p.is_stray and not p.is_found and matches(p)]
        if search_performed
        else []
    )

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "pets": pets,
        "page_type": "lost",
        "search_performed": search_performed,
        "filters": {
            "breed": request.query_params.get("breed", ""),
            "color": request.query_params.get("color", ""),
            "location": request.query_params.get("location", ""),
        },
    }
    return templates.TemplateResponse("lost_found_list.html", context)


@app.get("/found", tags=["Core Pages"])
def read_found_pets_page(request: Request):
    """List approved found-animal reports."""
    user_role, current_user = resolve_user(request)
    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()
    search_performed = any([filter_breed, filter_color, filter_location])

    def matches(p: PetInDB) -> bool:
        return (
            filter_breed in (p.breed or "").lower()
            and filter_color in (p.color or "").lower()
            and filter_location in (p.location_data or "").lower()
        )

    pets = (
        [p for p in approved_pets if p.is_found and matches(p)]
        if search_performed
        else []
    )

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "pets": pets,
        "page_type": "found",
        "search_performed": search_performed,
        "filters": {
            "breed": request.query_params.get("breed", ""),
            "color": request.query_params.get("color", ""),
            "location": request.query_params.get("location", ""),
        },
    }
    return templates.TemplateResponse("lost_found_list.html", context)


# --- 5. Login/Register Endpoints ---
# NOTE: Login/Register POST handlers omitted for brevity, focusing on pet flow

@app.get("/login", tags=["Authentication"])
def read_login_page(request: Request):
    error = request.query_params.get('error')
    success = request.query_params.get('success')
    context = {"request": request, "error": error, "success": success}
    return templates.TemplateResponse("login.html", context) 

@app.post("/login", tags=["Authentication"])
def process_login(request: Request, username: str = Form(...), password: str = Form(...)):
    # Rate limit check (per-IP)
    client_host = request.client.host if request.client else "unknown"
    now_ts = datetime.now(timezone.utc).timestamp()
    attempts = LOGIN_ATTEMPTS.get(client_host, [])
    # purge old attempts
    attempts = [ts for ts in attempts if now_ts - ts < LOGIN_WINDOW]
    if len(attempts) >= LOGIN_MAX_ATTEMPTS:
        return RedirectResponse(url="/login?error=Too+many+login+attempts", status_code=HTTP_303_SEE_OTHER)

    # Verify password using bcrypt
    user = next((u for u in users if u.email == username), None)
    if user and pwd_context.verify(password, user.password):
        # successful login: reset attempts
        LOGIN_ATTEMPTS[client_host] = []
        # Set session information for authenticated user
        request.session["user_id"] = str(user.user_id)
        request.session["user_role"] = user.role
        # Track last active for session timeout
        request.session["last_active"] = datetime.now(timezone.utc).isoformat()
        target = "/"
        if user.role == "admin":
            target = "/admin/dashboard"
        return RedirectResponse(url=target, status_code=HTTP_303_SEE_OTHER)

    # record failed attempt
    attempts.append(now_ts)
    LOGIN_ATTEMPTS[client_host] = attempts
    
    return RedirectResponse(
        url="/login?error=Invalid+email+or+password.",
        status_code=HTTP_303_SEE_OTHER
    )


@app.get("/logout", tags=["Authentication"])
def process_logout(request: Request):
    """Clears the user session and redirects to home."""
    request.session.clear()
    return RedirectResponse(url="/", status_code=HTTP_303_SEE_OTHER)

@app.get("/user-register", tags=["Authentication"])
def read_user_register_page(request: Request):
    error = request.query_params.get('error')
    success = request.query_params.get('success')
    context = {"request": request, "error": error, "success": success}
    return templates.TemplateResponse("user_register.html", context) 

@app.post("/user-register", tags=["Authentication"])
def process_user_registration(
    request: Request,
    first_name: str = Form(...),
    middle_name: Optional[str] = Form(None),
    last_name: str = Form(...),
    gender: Optional[str] = Form(None),
    date_of_birth: Optional[str] = Form(None),
    profile_photo: UploadFile = File(None),
    email: str = Form(...),
    mobile_number: str = Form(...),
    address: Optional[str] = Form(None),
    password: str = Form(...),
    confirm_password: str = Form(...),
    terms_accepted: bool = Form(False)
):
    """Handles user registration form submission with comprehensive user information."""
    
    # Validation: Check if passwords match
    if password != confirm_password:
        return RedirectResponse(
            url="/user-register?error=Passwords do not match.",
            status_code=HTTP_303_SEE_OTHER
        )
    
    # Validation: Check if terms are accepted
    if not terms_accepted:
        return RedirectResponse(
            url="/user-register?error=You must accept the Terms and Conditions to register.",
            status_code=HTTP_303_SEE_OTHER
        )

    # Check if user already exists
    if any(u.email == email for u in users):
        return RedirectResponse(
            url="/user-register?error=This email is already registered.",
            status_code=HTTP_303_SEE_OTHER
        )

    # Handle profile photo upload
    profile_photo_url = None
    if profile_photo and profile_photo.filename:
        profile_photo_url = save_upload_file(profile_photo)
    
    # Construct full_name from components
    name_parts = [first_name]
    if middle_name:
        name_parts.append(middle_name)
    name_parts.append(last_name)
    full_name = " ".join(name_parts).strip()

    # Register the new user as a standard 'user' (General User role)
    new_user = UserAccount(
        user_id=uuid4(),
        full_name=full_name, 
        first_name=first_name,
        middle_name=middle_name,
        last_name=last_name,
        email=email,
        password=pwd_context.hash(password),  # Store hashed password
        role="user",  # All new registrations are 'user' by default (General User)
        birthday=date_of_birth,
        address=address,
        contact_info=mobile_number,  # Store mobile in contact_info for backward compatibility
        mobile_number=mobile_number,
        gender=gender,
        profile_photo_url=profile_photo_url,
        notifications_enabled=True,
        privacy_public=True
    )
    users.append(new_user)
    save_state()
    
    logs.append(f"New user registered: {full_name} ({email})")
    save_state()

    # Redirect to the login page with a success message
    return RedirectResponse(
        url="/login?success=Registration successful! Your account has been created. Please log in.",
        status_code=HTTP_303_SEE_OTHER
    )

# --- 6. Admin Panel Endpoint (PROTECTED) ---

@app.get("/admin/dashboard", tags=["Admin Panel"])
def read_admin_dashboard(request: Request):
    """Admin dashboard with quick stats."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    total_registered = len(pending_pets) + len(approved_pets)
    total_verified = len([p for p in approved_pets if p.status == "approved" or p.status == "resolved"])
    pending_regs = len([p for p in pending_pets if p.status == "pending" or p.status == "info_needed"])
    reported_lost = len([p for p in pending_reports if p.is_stray and not p.is_found])
    reported_found = len([p for p in pending_reports if p.is_found]) + len([p for p in approved_pets if p.is_found])
    resolved_cases = len([p for p in approved_pets if p.status == "resolved"])
    active_users = len(users)

    # Add a simple search/filter and suggested matches for admin
    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()

    def matches(p: PetInDB) -> bool:
        return (filter_breed in p.breed.lower()) and (filter_color in p.color.lower()) and (filter_location in p.location_data.lower())

    # Suggested matches: for pending lost reports, find candidates in pending_found/approved lists
    all_candidates = pending_reports + approved_pets
    suggested_matches = {}
    # Use fuzzy matching (breed + color) for better suggested matches
    for lost in [p for p in pending_reports if p.is_stray and not p.is_found]:
        lb = (lost.breed or '').lower()
        lc = (lost.color or '').lower()
        matches_list = []
        for c in all_candidates:
            if c.pet_id == lost.pet_id:
                continue
            cb = (c.breed or '').lower()
            cc = (c.color or '').lower()
            # compute fuzzy scores for breed and color, take weighted average
            bscore = _safe_fuzzy_ratio(lb, cb) if lb and cb else 0
            cscore = _safe_fuzzy_ratio(lc, cc) if lc and cc else 0
            score = max(bscore, cscore, (bscore + cscore) // 2)
            if score >= 60:
                matches_list.append((score, c))
            matches_list = sorted(matches_list, key=lambda x: x[0], reverse=True)[:5]
        if matches_list:
            suggested_matches[str(lost.pet_id)] = [m[1] for m in matches_list]

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "stats": {
            "total_registered": total_registered,
            "total_verified": total_verified,
            "pending_regs": pending_regs,
            "reported_lost": reported_lost,
            "reported_found": reported_found,
            "resolved": resolved_cases,
            "active_users": active_users,
        },
        "logs": list(reversed(logs[-10:])),  # latest 10
        "suggested_matches": suggested_matches,
        "filters": {"breed": request.query_params.get("breed", ""), "color": request.query_params.get("color", ""), "location": request.query_params.get("location", "")}
    }
    return templates.TemplateResponse("admin_dashboard.html", context) 


@app.get("/user/dashboard", tags=["User Dashboard"])
def read_user_dashboard(request: Request):
    """Renders the user dashboard with profile summary, pets, reports, matches, and notifications."""
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    # Identify user's owned pets (both pending and approved)
    def owner_matches(p: PetInDB) -> bool:
        if not current_user:
            return False
        # Prefer explicit linkage via owner_user_id
        if getattr(p, "owner_user_id", None):
            return str(p.owner_user_id) == str(current_user.user_id)
        # Legacy fallback: match by contact info (not by name to avoid collisions)
        return (
            (p.owner_contact and current_user.contact_info and p.owner_contact == current_user.contact_info) or
            (p.owner_contact and current_user.mobile_number and p.owner_contact == current_user.mobile_number) or
            (p.owner_contact and current_user.email and p.owner_contact == current_user.email)
        )

    user_pets = [p for p in (approved_pets + pending_pets) if owner_matches(p)]

    # User's lost and found reports (reported by the user)
    def reporter_matches(p: PetInDB) -> bool:
        if not current_user:
            return False
        return (p.reporter_contact and (p.reporter_contact == current_user.contact_info or p.reporter_contact == current_user.mobile_number or p.reporter_contact == current_user.email))

    user_lost_reports = [p for p in (pending_reports + approved_pets) if p.is_stray and reporter_matches(p)]
    user_found_reports = [p for p in (pending_reports + approved_pets) if p.is_found and reporter_matches(p)]

    # Suggested matches: naive heuristic (breed or color matches)
    suggested_matches = {}
    suggestions_map = {}
    all_candidates = pending_reports + approved_pets
    # Use fuzzy matching (breed + color) for user suggestions as well
    for lost in user_lost_reports:
        suggestions_map[str(lost.pet_id)] = lost
        matches = []
        lb = (lost.breed or '').lower()
        lc = (lost.color or '').lower()
        scored = []
        for candidate in all_candidates:
            if str(candidate.pet_id) == str(lost.pet_id):
                continue
            cb = (candidate.breed or '').lower()
            cc = (candidate.color or '').lower()
            bscore = _safe_fuzzy_ratio(lb, cb) if lb and cb else 0
            cscore = _safe_fuzzy_ratio(lc, cc) if lc and cc else 0
            score = max(bscore, cscore, (bscore + cscore) // 2)
            if score >= 60:
                scored.append((score, candidate))
        scored = sorted(scored, key=lambda x: x[0], reverse=True)[:5]
        if scored:
            suggested_matches[str(lost.pet_id)] = [s[1] for s in scored]

    # Notifications: Get actual notifications for the user from the notifications list
    global notifications
    user_notifications = [n for n in notifications if n.user_id and str(n.user_id) == str(current_user.user_id)]
    
    # Sort notifications: unread first, then by timestamp (newest first)
    def sort_key(n):
        # Unread notifications come first (False sorts before True)
        read_priority = 0 if not n.read else 1
        # Parse timestamp for sorting (newest first)
        try:
            if hasattr(n, 'timestamp') and n.timestamp:
                ts = datetime.fromisoformat(n.timestamp.replace('Z', '+00:00'))
                timestamp_value = ts.timestamp()
            else:
                timestamp_value = 0
        except:
            timestamp_value = 0
        return (read_priority, -timestamp_value)  # Negative for descending order
    
    user_notifications.sort(key=sort_key)
    
    # Also add status updates related to user's pets/reports
    status_notifications = []
    for p in (user_pets + user_lost_reports + user_found_reports):
        status_notifications.append(f"{p.name}: status updated to {p.status}.")
    # Combine both types of notifications (Notification objects first, then status strings)
    all_notifications = user_notifications + status_notifications
    # Get published announcements
    announcements = [a for a in announcements_list if a.published]

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "user_pets": user_pets,
        "user_lost_reports": user_lost_reports,
        "user_found_reports": user_found_reports,
        "suggested_matches": suggested_matches,
        "suggestions_map": suggestions_map,
        "notifications": all_notifications,
        "announcements": announcements,
        "filters": {"breed": "", "color": "", "location": ""}
    }

    return templates.TemplateResponse("user_dashboard.html", context) 


@app.post("/user/pet/delete", status_code=HTTP_303_SEE_OTHER, tags=["User Dashboard"])
def delete_user_pet(request: Request, pet_id: str = Form(...)):
    role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    # find and remove from pending_pets or approved_pets
    for lst in (pending_pets, approved_pets):
        found = next((p for p in lst if str(p.pet_id) == pet_id), None)
        if found:
            # ownership check: prefer explicit owner_user_id, fallback to legacy matching
            owner_match = False
            if getattr(found, 'owner_user_id', None) and str(found.owner_user_id) == str(current_user.user_id):
                owner_match = True
            elif getattr(found, 'owner_name', None) == current_user.full_name or getattr(found, 'owner_contact', None) == current_user.contact_info or getattr(found, 'owner_contact', None) == current_user.mobile_number:
                owner_match = True
            if owner_match:
                lst.remove(found)
                logs.append(f"User {current_user.email} deleted pet {found.name}.")
                save_state()
            break

    return RedirectResponse(url=f"/user/dashboard", status_code=HTTP_303_SEE_OTHER)


@app.get("/user/pet/edit", tags=["User Dashboard"])
def get_edit_pet(request: Request, pet_id: str):
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    pet = next((p for p in approved_pets + pending_pets if str(p.pet_id) == pet_id), None)
    if not pet:
        return RedirectResponse(url=f"/user/dashboard?error=Pet+not+found", status_code=HTTP_303_SEE_OTHER)

    return templates.TemplateResponse(request, "edit_pet.html", {"request": request, "pet": pet, "user_role": user_role}) 


@app.post("/user/pet/edit", status_code=HTTP_303_SEE_OTHER, tags=["User Dashboard"])
def post_edit_pet(request: Request,
                  pet_id: str = Form(...),
                  name: str = Form(...),
                  breed: str = Form(None),
                  color: str = Form(None),
                  vaccination_status: bool = Form(False),
                  location_data: str = Form(None),
                  owner_name: str = Form(None),
                  owner_contact: str = Form(None),
                  photo_file: UploadFile = File(None)):
    role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    pet = next((p for p in approved_pets + pending_pets if str(p.pet_id) == pet_id), None)
    if not pet:
        return RedirectResponse(url=f"/user/dashboard?error=Pet+not+found", status_code=HTTP_303_SEE_OTHER)

    # Ownership check: prefer owner_user_id if present
    owner_match = False
    if pet.owner_user_id and str(pet.owner_user_id) == str(current_user.user_id):
        owner_match = True
    elif pet.owner_name == current_user.full_name or pet.owner_contact == current_user.contact_info or pet.owner_contact == current_user.mobile_number:
        owner_match = True
    if not owner_match:
        return RedirectResponse(url=f"/user/dashboard?error=Not+authorized", status_code=HTTP_303_SEE_OTHER)

    # Update fields
    pet.name = name
    pet.breed = breed or pet.breed
    pet.color = color or pet.color
    pet.vaccination_status = vaccination_status
    pet.location_data = location_data or pet.location_data
    pet.owner_name = owner_name or pet.owner_name
    pet.owner_contact = owner_contact or pet.owner_contact

    if photo_file and photo_file.filename:
        photo_url = save_upload_file(photo_file)
        if photo_url:
            pet.photo_url = photo_url

    logs.append(f"User {current_user.email} updated pet {pet.name} ({pet.pet_id}).")
    save_state()
    return RedirectResponse(url=f"/user/dashboard", status_code=HTTP_303_SEE_OTHER)


@app.post("/user/report/delete", status_code=HTTP_303_SEE_OTHER, tags=["User Dashboard"])
def delete_user_report(request: Request, report_id: str = Form(...)):
    role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    for lst in (pending_reports, approved_pets):
        found = next((p for p in lst if str(p.pet_id) == report_id), None)
        if found:
            # prefer reporter_user_id when present
            reporter_match = False
            if getattr(found, 'reporter_user_id', None) and str(found.reporter_user_id) == str(current_user.user_id):
                reporter_match = True
            elif getattr(found, 'reporter_contact', None) == current_user.contact_info or getattr(found, 'reporter_contact', None) == current_user.mobile_number or getattr(found, 'reporter_contact', None) == current_user.email:
                reporter_match = True
            if reporter_match:
                lst.remove(found)
                logs.append(f"User {current_user.email} deleted report {found.name}.")
                save_state()
            break

    return RedirectResponse(url=f"/user/dashboard", status_code=HTTP_303_SEE_OTHER)


@app.get("/user/case/{pet_id}", tags=["User Dashboard"])
def read_case_detail(request: Request, pet_id: str):
    user_role, current_user = resolve_user(request)
    if not current_user:
        return RedirectResponse(url="/login?error=Login required.", status_code=HTTP_303_SEE_OTHER)

    pet = next((p for p in (pending_reports + pending_pets + approved_pets) if str(p.pet_id) == pet_id), None)
    if not pet:
        return RedirectResponse(url=f"/user/dashboard?error=Case+not+found", status_code=HTTP_303_SEE_OTHER)

    context = {"request": request, "user_role": user_role, "current_user": current_user, "pet": pet}
    return templates.TemplateResponse(request, "case_detail.html", context) 


@app.get("/admin/users", tags=["Admin Panel"])
def read_admin_users(request: Request):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            "user_role": user_role,
            "current_user": current_user,
            "users": users,
        },
    )


@app.post("/admin/users/delete", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def delete_user(request: Request, user_id: str = Form(...)):
    """Delete a user from the system."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    
    global users
    try:
        user_uuid = UUID(user_id)
        # Prevent deleting the current admin user
        if str(user_uuid) == str(current_user.user_id):
            return RedirectResponse(url="/admin/users?error=Cannot delete your own account", status_code=HTTP_303_SEE_OTHER)
        
        # Find and remove the user
        user_to_delete = next((u for u in users if u.user_id == user_uuid), None)
        if user_to_delete:
            users.remove(user_to_delete)
            save_state()
            logs.append(f"Admin {current_user.full_name} deleted user {user_to_delete.full_name} ({user_to_delete.email})")
            save_state()
            return RedirectResponse(url="/admin/users?status=user_deleted", status_code=HTTP_303_SEE_OTHER)
        else:
            return RedirectResponse(url="/admin/users?error=User not found", status_code=HTTP_303_SEE_OTHER)
    except ValueError:
        return RedirectResponse(url="/admin/users?error=Invalid user ID", status_code=HTTP_303_SEE_OTHER)
    except Exception as e:
        logs.append(f"Error deleting user: {e}")
        save_state()
        return RedirectResponse(url="/admin/users?error=Error deleting user", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/export/pets.csv", tags=["Admin Panel"])
def admin_export_pets_csv(request: Request):
    """Admin-only CSV export of pets and reports."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    # Combine all lists into one export set
    rows = pending_pets + pending_reports + approved_pets
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["pet_id", "name", "breed", "color", "location_data", "is_stray", "status", "owner_name", "owner_contact", "reporter_contact", "date_reported"])
    for p in rows:
        writer.writerow([
            str(getattr(p, 'pet_id', '')),
            getattr(p, 'name', ''),
            getattr(p, 'breed', ''),
            getattr(p, 'color', ''),
            getattr(p, 'location_data', ''),
            str(getattr(p, 'is_stray', '')),
            getattr(p, 'status', ''),
            getattr(p, 'owner_name', '') or "",
            getattr(p, 'owner_contact', '') or "",
            getattr(p, 'reporter_contact', '') or "",
            getattr(p, 'date_reported', '') or "",
        ])
    csv_bytes = output.getvalue().encode('utf-8')
    from starlette.responses import Response
    headers = {"Content-Disposition": "attachment; filename=pet_export.csv"}
    return Response(content=csv_bytes, media_type="text/csv", headers=headers)


@app.get("/admin/export/pets.pdf", tags=["Admin Panel"])
def admin_export_pets_pdf(request: Request):
    """Admin-only PDF export of pets and reports."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    rows = pending_pets + pending_reports + approved_pets

    # Generate a simple PDF using reportlab
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except Exception:
        return RedirectResponse(url="/admin/dashboard?error=PDF+library+missing", status_code=HTTP_303_SEE_OTHER)

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = [Paragraph('Bantay PurrPaws - Pets & Reports Export', styles['Title']), Spacer(1, 12)]

    data = [["ID", "Name", "Breed", "Color", "Location", "Stray", "Status"]]
    for p in rows:
        data.append([
            str(getattr(p, 'pet_id', ''))[:8],
            getattr(p, 'name', ''),
            getattr(p, 'breed', ''),
            getattr(p, 'color', ''),
            getattr(p, 'location_data', ''),
            "Yes" if getattr(p, 'is_stray', False) else "No",
            getattr(p, 'status', ''),
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#b22222')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
    ]))
    flowables.append(table)
    doc.build(flowables)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    from starlette.responses import Response
    headers = {"Content-Disposition": "attachment; filename=pets_export.pdf"}
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


def generate_exports(created_by: Optional[UUID] = None) -> dict:
    """Generate CSV and PDF exports into EXPORT_DIR and return metadata dict."""
    _ensure_export_dir()
    rows = pending_pets + pending_reports + approved_pets
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    csv_name = f"pets_export_{ts}.csv"
    pdf_name = f"pets_export_{ts}.pdf"
    csv_path = os.path.abspath(os.path.join(EXPORT_DIR, csv_name))
    pdf_path = os.path.abspath(os.path.join(EXPORT_DIR, pdf_name))

    # Write CSV
    with open(csv_path, "w", encoding="utf-8", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["pet_id", "name", "breed", "color", "location_data", "is_stray", "status", "owner_name", "owner_contact", "reporter_contact", "date_reported"])
        for p in rows:
            writer.writerow([
                str(getattr(p, 'pet_id', '')),
                getattr(p, 'name', ''),
                getattr(p, 'breed', ''),
                getattr(p, 'color', ''),
                getattr(p, 'location_data', ''),
                str(getattr(p, 'is_stray', '')),
                getattr(p, 'status', ''),
                getattr(p, 'owner_name', '') or "",
                getattr(p, 'owner_contact', '') or "",
                getattr(p, 'reporter_contact', '') or "",
                getattr(p, 'date_reported', '') or "",
            ])

    # Write PDF (reusing the previous PDF generation logic)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
    except Exception:
        # If PDF library missing, still return CSV
        meta = {"export_id": str(uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(), "csv": csv_path, "pdf": None, "created_by": str(created_by) if created_by else None}
        exports.append(meta)
        save_state()
        return meta

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    flowables = [Paragraph('Bantay PurrPaws - Pets & Reports Export', styles['Title']), Spacer(1, 12)]

    data = [["ID", "Name", "Breed", "Color", "Location", "Stray", "Status"]]
    for p in rows:
        data.append([
            str(getattr(p, 'pet_id', ''))[:8],
            getattr(p, 'name', ''),
            getattr(p, 'breed', ''),
            getattr(p, 'color', ''),
            getattr(p, 'location_data', ''),
            "Yes" if getattr(p, 'is_stray', False) else "No",
            getattr(p, 'status', ''),
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#b22222')), ('TEXTCOLOR', (0, 0), (-1, 0), colors.white), ('GRID', (0, 0), (-1, -1), 0.5, colors.grey), ('ALIGN', (0, 0), (-1, -1), 'LEFT')]))
    flowables.append(table)
    doc.build(flowables)
    pdf_bytes = buffer.getvalue()
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)

    meta = {"export_id": str(uuid4()), "timestamp": datetime.now(timezone.utc).isoformat(), "csv": csv_path, "pdf": pdf_path, "created_by": str(created_by) if created_by else None}
    exports.append(meta)
    save_state()
    return meta


def check_and_run_scheduled_exports():
    """Iterate scheduled_exports and run any jobs that are due."""
    now = datetime.now(timezone.utc)
    attempted = []
    for job in scheduled_exports:
        try:
            last_run = job.get('last_run')
            freq = int(job.get('frequency_minutes', 0))
            run_now = False
            if last_run is None:
                run_now = True
            else:
                la = datetime.fromisoformat(last_run)
                if la.tzinfo is None:
                    la = la.replace(tzinfo=timezone.utc)
                age_minutes = (now - la).total_seconds() / 60.0
                if age_minutes >= freq:
                    run_now = True
            logs.append(f"Scheduled job check: id={job.get('job_id')}, last_run={last_run}, freq={freq}, run_now={run_now}")
            if run_now:
                try:
                    meta = generate_exports(created_by=job.get('created_by'))
                    logs.append(f"Scheduled job {job.get('job_id')} ran: {meta.get('export_id')}")
                except Exception as e:
                    logs.append(f"Scheduled job {job.get('job_id')} encountered error during export: {e}")
                finally:
                    # mark job as attempted so tests and operators know it ran at this time
                    job['last_run'] = datetime.now(timezone.utc).isoformat()
                    attempted.append(job.get('job_id'))
        except Exception as e:
            logs.append(f"Error running scheduled job {job.get('job_id')}: {e}")
    save_state()
    return attempted


def _scheduler_loop(poll_interval: int = 60):
    while not _scheduler_stop_event.is_set():
        try:
            check_and_run_scheduled_exports()
        except Exception:
            logs.append("Scheduler encountered an error during run.")
        _scheduler_stop_event.wait(poll_interval)


@app.on_event("startup")
def _maybe_start_scheduler():
    global _scheduler_thread
    if os.environ.get("ENABLE_SCHEDULER", "0") == "1":
        if not _scheduler_thread or not _scheduler_thread.is_alive():
            _scheduler_stop_event.clear()
            _scheduler_thread = threading.Thread(target=_scheduler_loop, args=(60,), daemon=True)
            _scheduler_thread.start()


@app.on_event("shutdown")
def _stop_scheduler():
    _scheduler_stop_event.set()
    if _scheduler_thread and _scheduler_thread.is_alive():
        _scheduler_thread.join(timeout=2)


@app.get("/admin/exports", tags=["Admin Panel"])
def read_admin_exports(request: Request):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "exports": exports,
        "scheduled": scheduled_exports,
    }
    return templates.TemplateResponse("admin_exports.html", context)


@app.post("/admin/exports/generate", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def admin_generate_exports(request: Request):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    meta = generate_exports(created_by=current_user.user_id if current_user else None)
    logs.append(f"Export generated: {meta.get('export_id')}")
    save_state()
    return RedirectResponse(url=f"/admin/exports?status=created", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/exports/generate", tags=["Admin Panel"])
def admin_generate_exports_get(request: Request):
    # Convenience GET endpoint to trigger generation from links (admin-only)
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    meta = generate_exports(created_by=current_user.user_id if current_user else None)
    logs.append(f"Export generated: {meta.get('export_id')}")
    save_state()
    return RedirectResponse(url=f"/admin/exports?status=created", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/exports/download/{export_id}/{filetype}", tags=["Admin Panel"])
def admin_export_download(request: Request, export_id: str, filetype: str):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    found = next((e for e in exports if e.get('export_id') == export_id), None)
    if not found:
        return RedirectResponse(url=f"/admin/exports?status=not_found", status_code=HTTP_303_SEE_OTHER)
    path = found.get('csv') if filetype == 'csv' else found.get('pdf')
    if not path or not os.path.exists(path):
        return RedirectResponse(url=f"/admin/exports?status=file_missing", status_code=HTTP_303_SEE_OTHER)
    from fastapi.responses import FileResponse
    return FileResponse(path, filename=os.path.basename(path))


@app.post("/admin/exports/schedule", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def admin_schedule_export(request: Request, frequency_minutes: int = Form(...), start_immediately: bool = Form(False)):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    job = {"job_id": str(uuid4()), "frequency_minutes": int(frequency_minutes), "created_by": str(current_user.user_id if current_user else None), "last_run": None}
    scheduled_exports.append(job)
    save_state()
    if start_immediately:
        generate_exports(created_by=current_user.user_id if current_user else None)
    return RedirectResponse(url=f"/admin/exports?status=scheduled", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/exports/run", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def admin_run_scheduled(request: Request):
    """Trigger scheduled job runner immediately (admin-only)."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    check_and_run_scheduled_exports()
    logs.append(f"Manual scheduled-run triggered by {current_user.email if current_user else 'unknown'}")
    return RedirectResponse(url=f"/admin/exports?status=ran", status_code=HTTP_303_SEE_OTHER)


@app.post("/admin/exports/unschedule", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def admin_unschedule_export(request: Request, job_id: str = Form(...)):
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    global scheduled_exports
    scheduled_exports = [j for j in scheduled_exports if j.get('job_id') != job_id]
    save_state()
    logs.append(f"Scheduled job {job_id} removed by {current_user.email if current_user else 'unknown'}")
    return RedirectResponse(url=f"/admin/exports?status=unscheduled", status_code=HTTP_303_SEE_OTHER)


@app.get("/admin/pending", tags=["Admin Panel"])
def read_admin_pending(request: Request):
    """Renders the pending requests page, only if admin."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        # REDIRECT TO LOGIN IF NOT ADMIN
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    status = request.query_params.get('status')

    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()

    def matches(p: PetInDB) -> bool:
        return (filter_breed in p.breed.lower()) and (filter_color in p.color.lower()) and (filter_location in p.location_data.lower())

    pending_regs = [p for p in pending_pets if not p.is_stray and p.status == "pending" and matches(p)]
    pending_lost_reports = [p for p in pending_reports if p.is_stray and not p.is_found and p.status == "pending" and matches(p)]
    pending_found_reports = [p for p in pending_reports if p.is_found and p.status == "pending" and matches(p)]
    info_reports = [p for p in pending_reports if p.status == "info_needed" and matches(p)]

    context = {
        "request": request,
        "current_user": current_user,
        "pending_regs": pending_regs,
        "pending_lost_reports": pending_lost_reports,
        "pending_found_reports": pending_found_reports,
        "info_reports": info_reports,
        "user_role": user_role,
        "status": status
    }
    return templates.TemplateResponse("admin_pending.html", context) 


@app.post("/admin/approve", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def approve_pet(request: Request, pet_id: str = Form(...)):
    """Moves a pet record from pending to the approved list."""
    # Use session to determine current user/role
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    pet_uuid = UUID(pet_id)
    
    global pending_pets, pending_reports, approved_pets
    
    # Check both pending lists
    pet_to_approve = next((p for p in pending_pets if p.pet_id == pet_uuid), None)
    if not pet_to_approve:
        pet_to_approve = next((p for p in pending_reports if p.pet_id == pet_uuid), None)
    
    if pet_to_approve:
        pet_to_approve.status = "approved"
        # Remove from whichever list it was found in
        if pet_to_approve in pending_pets:
            pending_pets.remove(pet_to_approve)
            # Add to approved registration history if it was a pet registration (not a stray report)
            if not pet_to_approve.is_stray:
                approved_registration_history.append(pet_to_approve)
        elif pet_to_approve in pending_reports:
            pending_reports.remove(pet_to_approve)
            
        # Add to approved list
        approved_pets.append(pet_to_approve)
        logs.append(f"Approved '{pet_to_approve.name}' ({pet_uuid}).")

        # Notify the owner/reporter if we can match them to a registered user
        recipient = None
        if pet_to_approve.owner_contact or pet_to_approve.owner_name:
            oc = pet_to_approve.owner_contact
            on = pet_to_approve.owner_name
            recipient = next((u for u in users if (oc and (u.contact_info == oc or u.mobile_number == oc or u.email == oc)) or (on and u.full_name == on)), None)
        if not recipient and pet_to_approve.reporter_contact:
            rc = pet_to_approve.reporter_contact
            recipient = next((u for u in users if u.contact_info == rc or u.mobile_number == rc or u.email == rc), None)

        if recipient:
            add_notification(recipient.user_id, f"Your case/pet '{pet_to_approve.name}' has been approved by admin.")

        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=approved",
            status_code=HTTP_303_SEE_OTHER
        )
    
    return RedirectResponse(
        url=f"/admin/pending?status=not_found",
        status_code=HTTP_303_SEE_OTHER
    )


@app.post("/admin/deny", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def deny_pet(request: Request, pet_id: str = Form(...)):
    """Removes a pending pet record."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    pet_uuid = UUID(pet_id)

    global pending_pets, pending_reports
    
    # Check both pending lists for removal
    pet_to_deny_in_pets = next((p for p in pending_pets if p.pet_id == pet_uuid), None)
    pet_to_deny_in_reports = next((p for p in pending_reports if p.pet_id == pet_uuid), None)

    if pet_to_deny_in_pets:
        pending_pets.remove(pet_to_deny_in_pets)
        logs.append(f"Denied registration '{pet_to_deny_in_pets.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=denied_pet",
            status_code=HTTP_303_SEE_OTHER
        )
    
    if pet_to_deny_in_reports:
        pending_reports.remove(pet_to_deny_in_reports)
        logs.append(f"Denied report '{pet_to_deny_in_reports.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=denied_report",
            status_code=HTTP_303_SEE_OTHER
        )
        
    return RedirectResponse(
        url=f"/admin/pending?status=not_found",
        status_code=HTTP_303_SEE_OTHER
    )


@app.post("/admin/request-info", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def request_info(request: Request, pet_id: str = Form(...), note: str = Form("", alias="note")):
    """Flags a pending record as needing more info."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    pet_uuid = UUID(pet_id)

    pet_in_pets = next((p for p in pending_pets if p.pet_id == pet_uuid), None)
    pet_in_reports = next((p for p in pending_reports if p.pet_id == pet_uuid), None)

    if pet_in_pets:
        pet_in_pets.status = "info_needed"
        if note:
            pet_in_pets.notes.append(note)
        logs.append(f"Info requested for '{pet_in_pets.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=info_needed",
            status_code=HTTP_303_SEE_OTHER
        )
    if pet_in_reports:
        pet_in_reports.status = "info_needed"
        if note:
            pet_in_reports.notes.append(note)
        logs.append(f"Info requested for report '{pet_in_reports.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=info_needed",
            status_code=HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url=f"/admin/pending?status=not_found",
        status_code=HTTP_303_SEE_OTHER
    )


@app.post("/admin/mark-found", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def mark_found(request: Request, pet_id: str = Form(...)):
    """Marks a report as found."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    pet_uuid = UUID(pet_id)

    pet_in_reports = next((p for p in pending_reports if p.pet_id == pet_uuid), None)
    pet_in_approved = next((p for p in approved_pets if p.pet_id == pet_uuid), None)

    if pet_in_reports:
        pet_in_reports.is_found = True
        pet_in_reports.status = "approved"
        pending_reports.remove(pet_in_reports)
        approved_pets.append(pet_in_reports)
        logs.append(f"Marked found report '{pet_in_reports.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=found",
            status_code=HTTP_303_SEE_OTHER
        )
    if pet_in_approved:
        pet_in_approved.is_found = True
        logs.append(f"Marked found approved item '{pet_in_approved.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=found",
            status_code=HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url=f"/admin/pending?status=not_found",
        status_code=HTTP_303_SEE_OTHER
    )


@app.post("/admin/resolve", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def resolve_record(request: Request, pet_id: str = Form(...)):
    """Marks a record as resolved."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
        
    pet_uuid = UUID(pet_id)

    # Try find in any list
    pet = next((p for p in pending_pets if p.pet_id == pet_uuid), None)
    if pet:
        pending_pets.remove(pet)
    else:
        pet = next((p for p in pending_reports if p.pet_id == pet_uuid), None)
        if pet:
            pending_reports.remove(pet)
        else:
            pet = next((p for p in approved_pets if p.pet_id == pet_uuid), None)

    if pet:
        pet.status = "resolved"
        if pet not in approved_pets:
            approved_pets.append(pet)
        logs.append(f"Resolved '{pet.name}' ({pet_uuid}).")
        save_state()
        return RedirectResponse(
            url=f"/admin/pending?status=resolved",
            status_code=HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url=f"/admin/pending?status=not_found",
        status_code=HTTP_303_SEE_OTHER
    )# --- Announcement Management (Admin Only) ---

@app.get("/admin/announcements/create", tags=["Admin Panel"])

def create_announcement_page(request: Request):

    """Admin page to create announcements."""

    user_role, current_user = resolve_user(request)

    if user_role != 'admin':

        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    context = {"request": request, "user_role": user_role, "current_user": current_user}

    return templates.TemplateResponse("admin_create_announcement.html", context)





@app.post("/admin/announcements/create", status_code=HTTP_303_SEE_OTHER, tags=["Admin Panel"])
def create_announcement(request: Request, title: str = Form(...), content: str = Form(...), published: str = Form("false")):
    """Create a new announcement (admin only)."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)
    
    # Check if published checkbox was checked (checkboxes send "true" or "on" when checked)
    is_published = published.lower() in ("true", "on")
    
    announcement = Announcement(
        announcement_id=uuid4(),
        title=title,
        content=content,
        created_by=current_user.user_id if current_user else None,
        created_at=datetime.now(timezone.utc).isoformat(),
        published=is_published
    )

    announcements_list.append(announcement)

    logs.append("Announcement '" + title + "' created by admin.")

    save_state()

    return RedirectResponse(url="/admin/dashboard?status=announcement_created", status_code=HTTP_303_SEE_OTHER)





@app.get("/admin/announcements", tags=["Admin Panel"])

def list_announcements(request: Request):

    """List all announcements (admin view)."""

    user_role, current_user = resolve_user(request)

    if user_role != 'admin':

        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    context = {

        "request": request,

        "user_role": user_role,

        "current_user": current_user,

        "announcements": sorted(announcements_list, key=lambda x: x.created_at, reverse=True)

    }

    return templates.TemplateResponse("admin_announcements.html", context)





# --- Community Stories/Reviews ---

@app.get("/community-stories", tags=["Core Pages"])

def community_stories_page(request: Request):

    """Display community stories/reviews."""

    user_role, current_user = resolve_user(request)

    context = {

        "request": request,

        "user_role": user_role,

        "current_user": current_user,

        "stories": sorted(community_stories, key=lambda x: x.created_at, reverse=True)

    }

    return templates.TemplateResponse("community_stories.html", context)





@app.post("/community-stories/submit", status_code=HTTP_303_SEE_OTHER, tags=["Core Pages"])

def submit_story(request: Request, rating: int = Form(...), feedback: str = Form(...)):

    """Submit a community story/review."""

    user_role, current_user = resolve_user(request)

    if not current_user:

        return RedirectResponse(url="/login?error=Login required to submit feedback.", status_code=HTTP_303_SEE_OTHER)

    

    if rating < 1 or rating > 5:

        return RedirectResponse(url="/community-stories?error=Rating must be between 1 and 5.", status_code=HTTP_303_SEE_OTHER)

    

    story = CommunityStory(

        story_id=uuid4(),

        user_id=current_user.user_id,

        user_name=current_user.full_name,

        rating=rating,

        feedback=feedback,

        created_at=datetime.now(timezone.utc).isoformat()

    )

    community_stories.append(story)

    logs.append("Community story submitted by " + current_user.full_name + ".")

    save_state()

    return RedirectResponse(url="/community-stories?status=submitted", status_code=HTTP_303_SEE_OTHER)





# --- Approved Registration History ---

@app.get("/admin/approved-history", tags=["Admin Panel"])
def approved_registration_history_page(request: Request):
    """View approved registration history."""
    user_role, current_user = resolve_user(request)
    if user_role != 'admin':
        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    filter_breed = request.query_params.get("breed", "").lower()
    filter_color = request.query_params.get("color", "").lower()
    filter_location = request.query_params.get("location", "").lower()

    def matches(p: PetInDB) -> bool:
        return (filter_breed in p.breed.lower()) and (filter_color in p.color.lower()) and (filter_location in p.location_data.lower())

    # Approved Registrations
    approved_regs = [p for p in approved_pets if not p.is_stray and matches(p)]
    # Approved Reports
    approved_reports = [p for p in approved_pets if p.is_stray and p.status == "approved" and matches(p)]
    # Resolved Reports
    resolved_reports = [p for p in approved_pets if p.status == "resolved" and matches(p)]

    context = {
        "request": request,
        "user_role": user_role,
        "current_user": current_user,
        "approved_history": sorted(approved_registration_history, key=lambda x: x.date_reported or "", reverse=True),
        "approved_regs": approved_regs,
        "approved_reports": approved_reports,
        "resolved_reports": resolved_reports,
    }
    return templates.TemplateResponse("admin_approved_history.html", context)





@app.get("/admin/approved-history/{pet_id}", tags=["Admin Panel"])

def approved_registration_details(request: Request, pet_id: str):

    """View details of an approved registration."""

    user_role, current_user = resolve_user(request)

    if user_role != 'admin':

        return RedirectResponse(url="/login?error=Admin access required.", status_code=HTTP_303_SEE_OTHER)

    

    pet_uuid = UUID(pet_id)

    pet = next((p for p in approved_registration_history if p.pet_id == pet_uuid), None)

    if not pet:

        return RedirectResponse(url="/admin/approved-history?error=not_found", status_code=HTTP_303_SEE_OTHER)

    

    context = {

        "request": request,

        "user_role": user_role,

        "current_user": current_user,

        "pet": pet

    }

    return templates.TemplateResponse(request, "approved_registration_detail.html", context)



