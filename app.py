import os

import requests
from flask import request, flash, redirect, url_for

TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_ENABLED = False

from functools import wraps
from datetime import datetime

import uuid

from datetime import datetime

from flask import jsonify

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
    current_app,
)
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from config import SECRET_KEY, PERMANENT_SESSION_LIFETIME
from services.db import get_connection
from services.availability_service import get_available_slots_for_day
from services.auth_service import (
    get_admin_by_email,
    get_admin_by_id,
    verify_password,
    update_admin_password,
)
from services.token_service import (
    create_password_reset_token,
    get_valid_reset_token,
    mark_token_as_used,
)

from datetime import datetime, timedelta

# =========================================================
# STAŁE / UPLOAD
# =========================================================

UPLOAD_EMPLOYEES_DIR = os.path.join("static", "images")
UPLOAD_BOOKING_SIDE_IMAGES_DIR = os.path.join("static", "uploads", "booking_side_images")

# =========================================================
# APP
# =========================================================

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = PERMANENT_SESSION_LIFETIME

# =========================================================
# BASIC HELPERS
# =========================================================

def get_settings():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM business_settings WHERE id = 1")
    settings = cursor.fetchone()

    conn.close()
    return settings


def admin_exists():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) AS total FROM admins")
    result = cursor.fetchone()

    conn.close()
    return result["total"] > 0


def login_admin(admin, remember_me=False):
    session["admin_logged_in"] = True
    session["admin_id"] = admin["id"]
    session["admin_email"] = admin["email"]
    session["admin_full_name"] = admin["full_name"]
    session.permanent = bool(remember_me)


def logout_admin():
    session.clear()


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Zaloguj się, aby uzyskać dostęp do panelu administratora.", "error")
            return redirect(url_for("admin_login"))
        return view_func(*args, **kwargs)

    return wrapper

def verify_turnstile_token(token: str, remote_ip: str | None = None) -> bool:
    if not TURNSTILE_SECRET_KEY or not token:
        return False

    payload = {
        "secret": TURNSTILE_SECRET_KEY,
        "response": token,
    }

    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
        return bool(result.get("success"))
    except Exception:
        return False


def find_waitlist_matches_for_slot(service_id, employee_id, booking_date, booking_time):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM waitlist_entries
            WHERE service_id = ?
              AND employee_id = ?
              AND status = 'waiting'
              AND (
                    preferred_date_from IS NULL
                    OR preferred_date_from = ''
                    OR preferred_date_from <= ?
                  )
              AND (
                    preferred_date_to IS NULL
                    OR preferred_date_to = ''
                    OR preferred_date_to >= ?
                  )
              AND (
                    preferred_time_from IS NULL
                    OR preferred_time_from = ''
                    OR preferred_time_from <= ?
                  )
              AND (
                    preferred_time_to IS NULL
                    OR preferred_time_to = ''
                    OR preferred_time_to >= ?
                  )
            ORDER BY created_at ASC, id ASC
            """,
            (service_id, employee_id, booking_date, booking_date, booking_time, booking_time)
        )
        return cursor.fetchall()
    finally:
        conn.close()


def mark_first_waitlist_match_for_slot(service_id, employee_id, booking_date, booking_time):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id
            FROM waitlist_entries
            WHERE service_id = ?
              AND employee_id = ?
              AND status = 'waiting'
              AND (
                    preferred_date_from IS NULL
                    OR preferred_date_from = ''
                    OR preferred_date_from <= ?
                  )
              AND (
                    preferred_date_to IS NULL
                    OR preferred_date_to = ''
                    OR preferred_date_to >= ?
                  )
              AND (
                    preferred_time_from IS NULL
                    OR preferred_time_from = ''
                    OR preferred_time_from <= ?
                  )
              AND (
                    preferred_time_to IS NULL
                    OR preferred_time_to = ''
                    OR preferred_time_to >= ?
                  )
            ORDER BY created_at ASC, id ASC
            LIMIT 1
        """, (
            service_id,
            employee_id,
            booking_date,
            booking_date,
            booking_time,
            booking_time
        ))

        match_row = cursor.fetchone()

        if not match_row:
            return

        cursor.execute("""
            UPDATE waitlist_entries
            SET
                status = 'matched',
                matched_booking_date = ?,
                matched_booking_time = ?
            WHERE id = ?
        """, (
            booking_date,
            booking_time,
            match_row["id"]
        ))

        conn.commit()

    finally:
        conn.close()        



def clear_waitlist_match(waitlist_entry_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE waitlist_entries
            SET
                status = 'waiting',
                matched_booking_date = NULL,
                matched_booking_time = NULL
            WHERE id = ?
        """, (waitlist_entry_id,))
        conn.commit()
    finally:
        conn.close()
# =========================================================
# DATE / TIME HELPERS
# =========================================================

def get_weekday_key(date_str: str) -> str:
    dt = datetime.strptime(date_str, "%Y-%m-%d")

    weekday_map = {
        0: "mon",
        1: "tue",
        2: "wed",
        3: "thu",
        4: "fri",
        5: "sat",
        6: "sun",
    }

    return weekday_map[dt.weekday()]


def normalize_time_value(value: str | None) -> str:
    return (value or "").strip()

def delete_static_file(relative_path: str | None):
    if not relative_path:
        return

    file_path = os.path.join(app.static_folder, relative_path)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass


# =========================================================
# CLOSED DAYS
# =========================================================

def is_closed_day(date_str: str) -> bool:
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM closed_days
            WHERE closed_date = ?
            LIMIT 1
            """,
            (date_str,)
        )
        row = cursor.fetchone()
        return row is not None
    finally:
        conn.close()


# =========================================================
# EMPLOYEE SCHEDULE MAPS
# =========================================================

def build_employee_schedule_map():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT employee_id, day_key, enabled, start_time, end_time
            FROM employee_work_schedule
            ORDER BY employee_id, id
            """
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    schedule_map = {}

    for row in rows:
        employee_id = row["employee_id"]
        day_key = row["day_key"]

        if employee_id not in schedule_map:
            schedule_map[employee_id] = {}

        schedule_map[employee_id][day_key] = {
            "enabled": int(row["enabled"]) == 1,
            "start_time": row["start_time"] or "",
            "end_time": row["end_time"] or "",
        }

    return schedule_map


def build_employee_time_off_map(employee_ids):
    if not employee_ids:
        return {}

    conn = get_connection()
    cursor = conn.cursor()

    try:
        placeholders = ",".join(["?"] * len(employee_ids))
        cursor.execute(
            f"""
            SELECT id, employee_id, type, date_from, date_to, note
            FROM employee_time_off
            WHERE employee_id IN ({placeholders})
            ORDER BY date_from ASC, id ASC
            """,
            employee_ids
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    result = {
        employee_id: {
            "vacation": [],
            "sick_leave": [],
        }
        for employee_id in employee_ids
    }

    for row in rows:
        item = {
            "id": row["id"],
            "date_from": row["date_from"],
            "date_to": row["date_to"],
            "note": row["note"] or "",
        }

        if row["type"] == "vacation":
            result[row["employee_id"]]["vacation"].append(item)
        elif row["type"] == "sick_leave":
            result[row["employee_id"]]["sick_leave"].append(item)

    return result


def build_employee_schedule_exceptions_map(employee_ids):
    if not employee_ids:
        return {}

    conn = get_connection()
    cursor = conn.cursor()

    try:
        placeholders = ",".join(["?"] * len(employee_ids))
        cursor.execute(
            f"""
            SELECT id, employee_id, exception_date, is_day_off, start_time, end_time, note
            FROM employee_schedule_exceptions
            WHERE employee_id IN ({placeholders})
            ORDER BY exception_date ASC, id ASC
            """,
            employee_ids
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    result = {employee_id: [] for employee_id in employee_ids}

    for row in rows:
        result[row["employee_id"]].append({
            "id": row["id"],
            "exception_date": row["exception_date"],
            "is_day_off": int(row["is_day_off"]) == 1,
            "start_time": row["start_time"] or "",
            "end_time": row["end_time"] or "",
            "note": row["note"] or "",
        })

    return result


# =========================================================
# EMPLOYEE SINGLE-DAY LOOKUPS
# =========================================================

def get_employee_schedule_for_weekday(employee_id: int, day_key: str):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT employee_id, day_key, enabled, start_time, end_time
            FROM employee_work_schedule
            WHERE employee_id = ? AND day_key = ?
            LIMIT 1
            """,
            (employee_id, day_key)
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    return {
        "employee_id": row["employee_id"],
        "day_key": row["day_key"],
        "enabled": int(row["enabled"]) == 1,
        "start_time": row["start_time"] or "",
        "end_time": row["end_time"] or "",
    }


def get_employee_schedule_exception_for_date(employee_id: int, date_str: str):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, employee_id, exception_date, is_day_off, start_time, end_time, note
            FROM employee_schedule_exceptions
            WHERE employee_id = ? AND exception_date = ?
            LIMIT 1
            """,
            (employee_id, date_str)
        )
        row = cursor.fetchone()
    finally:
        conn.close()

    if not row:
        return None

    return {
        "id": row["id"],
        "employee_id": row["employee_id"],
        "exception_date": row["exception_date"],
        "is_day_off": int(row["is_day_off"]) == 1,
        "start_time": row["start_time"] or "",
        "end_time": row["end_time"] or "",
        "note": row["note"] or "",
    }


def employee_has_time_off_on_date(employee_id: int, date_str: str):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, employee_id, type, date_from, date_to, note
            FROM employee_time_off
            WHERE employee_id = ?
              AND date(?) BETWEEN date(date_from) AND date(date_to)
            ORDER BY id ASC
            """,
            (employee_id, date_str)
        )
        rows = cursor.fetchall()
    finally:
        conn.close()

    result = {
        "has_time_off": len(rows) > 0,
        "vacation": [],
        "sick_leave": [],
    }

    for row in rows:
        item = {
            "id": row["id"],
            "date_from": row["date_from"],
            "date_to": row["date_to"],
            "note": row["note"] or "",
        }

        if row["type"] == "vacation":
            result["vacation"].append(item)
        elif row["type"] == "sick_leave":
            result["sick_leave"].append(item)

    return result


def normalize_client_lookup_value(value: str | None) -> str:
    return (value or "").strip().lower()


def get_client_by_phone_or_email(phone: str | None, email: str | None):
    normalized_phone = (phone or "").strip()
    normalized_email = normalize_client_lookup_value(email)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        if normalized_phone:
            cursor.execute(
                """
                SELECT *
                FROM clients
                WHERE phone = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (normalized_phone,)
            )
            row = cursor.fetchone()
            if row:
                return row

        if normalized_email:
            cursor.execute(
                """
                SELECT *
                FROM clients
                WHERE LOWER(COALESCE(email, '')) = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (normalized_email,)
            )
            row = cursor.fetchone()
            if row:
                return row

        return None
    finally:
        conn.close()


def get_or_create_client(
    full_name: str,
    phone: str | None = None,
    email: str | None = None,
    privacy_consent: int = 0,
    marketing_consent: int = 0,
    consent_source: str | None = None,
    consent_timestamp: str | None = None,
):
    full_name = (full_name or "").strip()
    phone = (phone or "").strip()
    email = (email or "").strip()
    consent_source = (consent_source or "").strip() or None
    consent_timestamp = (consent_timestamp or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not full_name:
        return None

    existing_client = get_client_by_phone_or_email(phone, email)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        if existing_client:
            update_name = full_name or existing_client["full_name"]
            update_phone = phone or existing_client["phone"]
            update_email = email or existing_client["email"]

            current_privacy_consent = int(existing_client["privacy_consent"] or 0) if "privacy_consent" in existing_client.keys() else 0
            current_marketing_consent = int(existing_client["marketing_consent"] or 0) if "marketing_consent" in existing_client.keys() else 0
            current_privacy_consent_at = existing_client["privacy_consent_at"] if "privacy_consent_at" in existing_client.keys() else None
            current_marketing_consent_at = existing_client["marketing_consent_at"] if "marketing_consent_at" in existing_client.keys() else None
            current_consent_source = existing_client["consent_source"] if "consent_source" in existing_client.keys() else None

            new_privacy_consent = 1 if current_privacy_consent == 1 or privacy_consent == 1 else 0
            new_marketing_consent = 1 if current_marketing_consent == 1 or marketing_consent == 1 else 0

            new_privacy_consent_at = current_privacy_consent_at
            if privacy_consent == 1 and not current_privacy_consent_at:
                new_privacy_consent_at = consent_timestamp

            new_marketing_consent_at = current_marketing_consent_at
            if marketing_consent == 1 and not current_marketing_consent_at:
                new_marketing_consent_at = consent_timestamp

            new_consent_source = current_consent_source or consent_source

            cursor.execute(
                """
                UPDATE clients
                SET
                    full_name = ?,
                    phone = ?,
                    email = ?,
                    privacy_consent = ?,
                    marketing_consent = ?,
                    privacy_consent_at = ?,
                    marketing_consent_at = ?,
                    consent_source = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    update_name,
                    update_phone or None,
                    update_email or None,
                    new_privacy_consent,
                    new_marketing_consent,
                    new_privacy_consent_at,
                    new_marketing_consent_at,
                    new_consent_source,
                    now_str,
                    existing_client["id"],
                )
            )
            conn.commit()
            return existing_client["id"]

        cursor.execute(
            """
            INSERT INTO clients (
                full_name,
                phone,
                email,
                client_status,
                is_regular,
                notes,
                privacy_consent,
                marketing_consent,
                privacy_consent_at,
                marketing_consent_at,
                consent_source,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                full_name,
                phone or None,
                email or None,
                "standard",
                0,
                None,
                1 if privacy_consent == 1 else 0,
                1 if marketing_consent == 1 else 0,
                consent_timestamp if privacy_consent == 1 else None,
                consent_timestamp if marketing_consent == 1 else None,
                consent_source,
                now_str,
                now_str,
            )
        )
        conn.commit()
        return cursor.lastrowid

    finally:
        conn.close()


# =========================================================
# FINAL RESOLUTION FOR BOOKING
# =========================================================

def resolve_employee_working_hours_for_date(employee_id: int, date_str: str):
    """
    Priorytet dla konkretnej daty:
    1. globalny dzień wyłączony
    2. urlop / chorobowe pracownika
    3. wyjątek dla konkretnej daty
    4. zwykły tygodniowy grafik
    """

    if is_closed_day(date_str):
        return {
            "available": False,
            "reason": "closed_day",
            "start_time": None,
            "end_time": None,
        }

    time_off = employee_has_time_off_on_date(employee_id, date_str)
    if time_off["has_time_off"]:
        return {
            "available": False,
            "reason": "employee_time_off",
            "start_time": None,
            "end_time": None,
        }

    exception_data = get_employee_schedule_exception_for_date(employee_id, date_str)
    if exception_data:
        if exception_data["is_day_off"]:
            return {
                "available": False,
                "reason": "exception_day_off",
                "start_time": None,
                "end_time": None,
            }

        start_time = normalize_time_value(exception_data["start_time"])
        end_time = normalize_time_value(exception_data["end_time"])

        if not start_time or not end_time:
            return {
                "available": False,
                "reason": "exception_missing_hours",
                "start_time": None,
                "end_time": None,
            }

        return {
            "available": True,
            "reason": "schedule_exception",
            "start_time": start_time,
            "end_time": end_time,
        }

    weekday_key = get_weekday_key(date_str)
    weekday_schedule = get_employee_schedule_for_weekday(employee_id, weekday_key)

    if not weekday_schedule or not weekday_schedule["enabled"]:
        return {
            "available": False,
            "reason": "weekday_off",
            "start_time": None,
            "end_time": None,
        }

    start_time = normalize_time_value(weekday_schedule["start_time"])
    end_time = normalize_time_value(weekday_schedule["end_time"])

    if not start_time or not end_time:
        return {
            "available": False,
            "reason": "missing_hours",
            "start_time": None,
            "end_time": None,
        }

    return {
        "available": True,
        "reason": "weekly_schedule",
        "start_time": start_time,
        "end_time": end_time,
    }


def get_booking_side_images(side=None, only_active=True, limit=None):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        query = """
            SELECT *
            FROM booking_side_images
            WHERE 1 = 1
        """
        params = []

        if side in ("left", "right"):
            query += " AND side = ?"
            params.append(side)

        if only_active:
            query += " AND is_active = 1"

        query += " ORDER BY sort_order ASC, id ASC"

        if isinstance(limit, int) and limit > 0:
            query += " LIMIT ?"
            params.append(limit)

        cursor.execute(query, params)
        return cursor.fetchall()

    finally:
        conn.close()



# =========================================================
# SETUP / AUTH
# =========================================================

@app.route("/setup", methods=["GET", "POST"])
def setup_admin():
    settings = get_settings()

    if admin_exists():
        flash("Konto administratora już istnieje. Zaloguj się.", "info")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password or not confirm_password:
            flash("Wypełnij wszystkie pola.", "error")
            return render_template(
                "setup_admin.html",
                page_title="Pierwsza konfiguracja",
                settings=settings
            )

        if password != confirm_password:
            flash("Hasła nie są takie same.", "error")
            return render_template(
                "setup_admin.html",
                page_title="Pierwsza konfiguracja",
                settings=settings
            )

        if len(password) < 8:
            flash("Hasło musi mieć co najmniej 8 znaków.", "error")
            return render_template(
                "setup_admin.html",
                page_title="Pierwsza konfiguracja",
                settings=settings
            )

        password_hash = generate_password_hash(password)
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO admins (email, password_hash, full_name, is_active, created_at)
                VALUES (?, ?, ?, 1, ?)
            """, (email, password_hash, full_name, created_at))
            conn.commit()
            flash("Konto administratora zostało utworzone. Możesz się zalogować.", "success")
            return redirect(url_for("admin_login"))
        except Exception:
            flash("Nie udało się utworzyć konta administratora.", "error")
            return render_template(
                "setup_admin.html",
                page_title="Pierwsza konfiguracja",
                settings=settings
            )
        finally:
            conn.close()

    return render_template(
        "setup_admin.html",
        page_title="Pierwsza konfiguracja",
        settings=settings
    )


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    settings = get_settings()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == "1"

        admin = get_admin_by_email(email)

        if not admin or admin["is_active"] != 1:
            flash("Nieprawidłowy e-mail lub hasło.", "error")
            return render_template(
                "admin_login.html",
                page_title="Logowanie administratora",
                settings=settings
            )

        if not verify_password(password, admin["password_hash"]):
            flash("Nieprawidłowy e-mail lub hasło.", "error")
            return render_template(
                "admin_login.html",
                page_title="Logowanie administratora",
                settings=settings
            )

        login_admin(admin, remember_me=remember_me)
        flash("Zalogowano pomyślnie.", "success")
        return redirect(url_for("admin_dashboard"))

    return render_template(
        "admin_login.html",
        page_title="Logowanie administratora",
        settings=settings
    )


@app.route("/admin/logout")
def admin_logout():
    logout_admin()
    flash("Zostałeś wylogowany.", "success")
    return redirect(url_for("admin_login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    settings = get_settings()

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        admin = get_admin_by_email(email)

        if admin:
            token = create_password_reset_token(admin["id"])
            reset_link = url_for("reset_password", token=token, _external=True)

            print("=" * 80)
            print("LINK DO RESETU HASŁA:")
            print(reset_link)
            print("=" * 80)

        flash("Jeśli konto istnieje, link do resetu hasła został wygenerowany.", "success")
        return redirect(url_for("admin_login"))

    return render_template(
        "forgot_password.html",
        page_title="Reset hasła",
        settings=settings
    )


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    settings = get_settings()
    token_row = get_valid_reset_token(token)

    if not token_row:
        flash("Link do resetu hasła jest nieprawidłowy lub wygasł.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not password or not confirm_password:
            flash("Proszę uzupełnić wszystkie pola.", "error")
            return render_template(
                "reset_password.html",
                page_title="Nowe hasło",
                settings=settings,
                token=token
            )

        if password != confirm_password:
            flash("Hasła nie są takie same.", "error")
            return render_template(
                "reset_password.html",
                page_title="Nowe hasło",
                settings=settings,
                token=token
            )

        if len(password) < 8:
            flash("Hasło musi mieć co najmniej 8 znaków.", "error")
            return render_template(
                "reset_password.html",
                page_title="Nowe hasło",
                settings=settings,
                token=token
            )

        update_admin_password(token_row["admin_id"], password)
        mark_token_as_used(token_row["id"])

        flash("Hasło zostało zmienione. Możesz się zalogować.", "success")
        return redirect(url_for("admin_login"))

    return render_template(
        "reset_password.html",
        page_title="Nowe hasło",
        settings=settings,
        token=token
    )


@app.route("/admin/change-password", methods=["GET", "POST"])
@admin_required
def admin_change_password():
    settings = get_settings()
    admin = get_admin_by_id(session["admin_id"])

    if not admin:
        logout_admin()
        flash("Sesja wygasła. Zaloguj się ponownie.", "error")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_new_password = request.form.get("confirm_new_password", "")

        if not current_password or not new_password or not confirm_new_password:
            flash("Proszę uzupełnić wszystkie pola.", "error")
            return render_template(
                "admin_change_password.html",
                page_title="Zmiana hasła",
                settings=settings
            )

        if not verify_password(current_password, admin["password_hash"]):
            flash("Obecne hasło jest nieprawidłowe.", "error")
            return render_template(
                "admin_change_password.html",
                page_title="Zmiana hasła",
                settings=settings
            )

        if new_password != confirm_new_password:
            flash("Nowe hasła nie są takie same.", "error")
            return render_template(
                "admin_change_password.html",
                page_title="Zmiana hasła",
                settings=settings
            )

        if len(new_password) < 8:
            flash("Nowe hasło musi mieć co najmniej 8 znaków.", "error")
            return render_template(
                "admin_change_password.html",
                page_title="Zmiana hasła",
                settings=settings
            )

        update_admin_password(admin["id"], new_password)
        flash("Hasło zostało zmienione.", "success")
        return redirect(url_for("admin_settings"))

    return render_template(
        "admin_change_password.html",
        page_title="Zmiana hasła",
        settings=settings
    )


# =========================================================
# PUBLIC PAGES
# =========================================================

@app.route("/")
def booking():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT
            s.id AS service_id,
            s.name AS service_name,
            s.duration_minutes,
            s.price,
            s.service_group,
            e.id AS employee_id,
            e.full_name AS employee_name,
            e.role AS employee_role,
            e.photo_path AS employee_photo_path
        FROM services s
        JOIN service_employees se ON se.service_id = s.id
        JOIN employees e ON e.id = se.employee_id
        WHERE s.active = 1
          AND e.active = 1
        ORDER BY
            CASE
                WHEN s.service_group IS NULL OR TRIM(s.service_group) = '' THEN 1
                ELSE 0
            END,
            s.service_group,
            s.name,
            e.full_name
    """)
    rows = cursor.fetchall()

    settings = get_settings()
    conn.close()

    services_grouped = {}
    services_map = {}

    for row in rows:
        group_name = (
            row["service_group"].strip()
            if row["service_group"] and row["service_group"].strip()
            else "Pozostałe"
        )

        service_id = row["service_id"]

        if service_id not in services_map:
            service_data = {
                "service_id": service_id,
                "service_name": row["service_name"],
                "duration_minutes": row["duration_minutes"],
                "price": row["price"],
                "service_group": group_name,
                "employees": []
            }

            services_map[service_id] = service_data

            if group_name not in services_grouped:
                services_grouped[group_name] = []

            services_grouped[group_name].append(service_data)

        services_map[service_id]["employees"].append({
            "employee_id": row["employee_id"],
            "employee_name": row["employee_name"],
            "employee_role": row["employee_role"] or "",
            "employee_photo_path": row["employee_photo_path"] or ""
        })

    booking_left_images = get_booking_side_images(side="left", only_active=True)
    booking_right_images = get_booking_side_images(side="right", only_active=True)

    booking_left_image = booking_left_images[0] if booking_left_images else None
    booking_right_image = booking_right_images[0] if booking_right_images else None

    waitlist_redirect_context = session.pop("waitlist_redirect_context", None)
    open_slots = request.args.get("open_slots") == "1"

    return render_template(
        "booking.html",
        page_title="Rezerwacja",
        services_grouped=services_grouped,
        settings=settings,
        waitlist_redirect_context=waitlist_redirect_context,
        open_slots=open_slots,
        booking_left_image=booking_left_image,
        booking_right_image=booking_right_image,
        booking_left_images=booking_left_images,
        booking_right_images=booking_right_images
    )

@app.route("/polityka-prywatnosci")
def privacy_policy():
    settings = get_settings()
    return render_template(
        "privacy_policy.html",
        page_title="Polityka prywatności",
        settings=settings
    )


@app.route("/api/available-slots")
def available_slots():
    service_id = request.args.get("service_id", type=int)
    employee_id = request.args.get("employee_id", type=int)
    booking_date = request.args.get("booking_date", "").strip()

    if not service_id or not employee_id or not booking_date:
        return jsonify({"slots": []})

    try:
        slots = get_available_slots_for_day(service_id, employee_id, booking_date)
        return jsonify({"slots": slots})
    except Exception:
        return jsonify({"slots": []}), 500


@app.route("/book", methods=["POST"])
def create_booking():
    service_id = request.form.get("service_id", type=int)
    employee_id = request.form.get("employee_id", type=int)

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()

    booking_date = (request.form.get("booking_date") or "").strip()
    booking_time = (request.form.get("booking_time") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    privacy_consent = 1 if request.form.get("privacy_consent") else 0
    marketing_consent = 1 if request.form.get("marketing_consent") == "1" else 0

    consents_created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not service_id or not employee_id or not client_name or not client_phone or not booking_date or not booking_time:
        flash("Proszę uzupełnić wszystkie wymagane pola.", "error")
        return redirect(url_for("booking"))

    if not privacy_consent:
        flash(
            "Aby zarezerwować termin, należy potwierdzić zapoznanie się z polityką prywatności.",
            "error"
        )
        return redirect(url_for("booking"))

    if TURNSTILE_ENABLED:
        turnstile_token = (request.form.get("cf-turnstile-response") or "").strip()
        if not verify_turnstile_token(turnstile_token, request.remote_addr):
            flash("Weryfikacja bezpieczeństwa nie powiodła się. Spróbuj ponownie.", "error")
            return redirect(url_for("booking"))

    available_slots = get_available_slots_for_day(service_id, employee_id, booking_date)

    if booking_time not in available_slots:
        flash("Wybrany termin nie jest już dostępny.", "error")
        return redirect(url_for("booking"))

    client_id = get_or_create_client(
        full_name=client_name,
        phone=client_phone,
        email=client_email,
        privacy_consent=privacy_consent,
        marketing_consent=marketing_consent,
        consent_source="booking_form",
        consent_timestamp=consents_created_at
    )

    if not client_id:
        flash("Nie udało się utworzyć lub odnaleźć karty klienta.", "error")
        return redirect(url_for("booking"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO bookings (
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email,
                client_phone,
                booking_date,
                booking_time,
                notes,
                status,
                privacy_consent,
                marketing_consent,
                consents_created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email or None,
                client_phone,
                booking_date,
                booking_time,
                notes or None,
                "new",
                privacy_consent,
                marketing_consent,
                consents_created_at
            )
        )
        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd create_booking:", e)
        flash("Nie udało się zapisać rezerwacji. Spróbuj ponownie.", "error")
        return redirect(url_for("booking"))

    finally:
        conn.close()

    flash("Rezerwacja została zapisana.", "success")
    return redirect(url_for("booking"))

# =========================================================
# ADMIN DASHBOARD / BOOKINGS
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_connection()
    cursor = conn.cursor()

    settings = get_settings()

    today = datetime.now().strftime("%Y-%m-%d")
    archived_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        UPDATE bookings
        SET
            archived = 1,
            archived_at = ?,
            archived_reason = ?
        WHERE COALESCE(archived, 0) = 0
          AND booking_date < ?
    """, (archived_at, "completed_previous_day", today))

    conn.commit()

    cursor.execute("""
        SELECT
            bookings.id,
            bookings.client_name,
            bookings.client_email,
            bookings.client_phone,
            bookings.booking_date,
            bookings.booking_time,
            bookings.notes,
            bookings.status,
            bookings.employee_id,
            services.name AS service_name,
            employees.full_name AS employee_name
        FROM bookings
        LEFT JOIN services ON bookings.service_id = services.id
        LEFT JOIN employees ON bookings.employee_id = employees.id
        WHERE COALESCE(bookings.archived, 0) = 0
        ORDER BY bookings.booking_date DESC, bookings.booking_time DESC, bookings.id DESC
    """)
    bookings = cursor.fetchall()

    cursor.execute("""
        SELECT
            bookings.id,
            bookings.client_name,
            bookings.client_email,
            bookings.client_phone,
            bookings.booking_date,
            bookings.booking_time,
            bookings.notes,
            bookings.status,
            bookings.employee_id,
            services.name AS service_name,
            employees.full_name AS employee_name
        FROM bookings
        LEFT JOIN services ON bookings.service_id = services.id
        LEFT JOIN employees ON bookings.employee_id = employees.id
        WHERE COALESCE(bookings.archived, 0) = 1
        ORDER BY bookings.booking_date DESC, bookings.booking_time DESC, bookings.id DESC
    """)
    archived_bookings = cursor.fetchall()

    cursor.execute("""
        SELECT id, full_name
        FROM employees
        WHERE active = 1
        ORDER BY full_name ASC
    """)
    employees = cursor.fetchall()

    cursor.execute("""
        SELECT
            id,
            name,
            service_group,
            duration_minutes,
            price
        FROM services
        WHERE active = 1
        ORDER BY
            CASE
                WHEN service_group IS NULL OR TRIM(service_group) = '' THEN 1
                ELSE 0
            END,
            service_group,
            name
    """)

    manual_booking_services = []

    for row in cursor.fetchall():
        item = dict(row)
        item["group_name"] = (
            row["service_group"].strip()
            if row["service_group"] and row["service_group"].strip()
            else "Pozostałe"
        )
        manual_booking_services.append(item)

    cursor.execute("""
        SELECT
            w.id,
            w.client_name,
            w.client_email,
            w.client_phone,
            w.preferred_date_from,
            w.preferred_date_to,
            w.preferred_time_from,
            w.preferred_time_to,
            w.notes,
            w.status,
            w.created_at,
            w.matched_booking_date,
            w.matched_booking_time,
            s.name AS service_name,
            e.full_name AS employee_name
        FROM waitlist_entries w
        LEFT JOIN services s ON w.service_id = s.id
        LEFT JOIN employees e ON w.employee_id = e.id
        WHERE w.status IN ('waiting', 'matched', 'booked')
        ORDER BY
            CASE
                WHEN w.status = 'matched' THEN 0
                ELSE 1
            END,
            w.created_at ASC,
            w.id ASC
    """)
    waitlist_entries = cursor.fetchall()

    conn.close()

    return render_template(
        "admin_dashboard.html",
        page_title="Panel administracyjny",
        settings=settings,
        bookings=bookings,
        archived_bookings=archived_bookings,
        employees=employees,
        manual_booking_services=manual_booking_services,
        waitlist_entries=waitlist_entries
    )


@app.route("/admin/bookings/<int:booking_id>/status", methods=["POST"])
@admin_required
def update_booking_status(booking_id):
    status = (request.form.get("status") or "").strip()

    allowed_statuses = ["new", "confirmed", "cancelled"]
    if status not in allowed_statuses:
        flash("Nieprawidłowy status.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT service_id, employee_id, booking_date, booking_time, status
            FROM bookings
            WHERE id = ?
            LIMIT 1
            """,
            (booking_id,)
        )
        booking_row = cursor.fetchone()

        if not booking_row:
            flash("Nie znaleziono rezerwacji.", "error")
            return redirect(url_for("admin_dashboard"))

        previous_status = (booking_row["status"] or "").strip().lower()

        cursor.execute(
            """
            UPDATE bookings
            SET status = ?
            WHERE id = ?
            """,
            (status, booking_id)
        )
        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd update_booking_status:", e)
        flash("Nie udało się zaktualizować statusu rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()

    if status == "cancelled" and previous_status != "cancelled":
        mark_first_waitlist_match_for_slot(
            booking_row["service_id"],
            booking_row["employee_id"],
            booking_row["booking_date"],
            booking_row["booking_time"]
        )

    flash("Status rezerwacji został zaktualizowany.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bookings/<int:booking_id>/delete", methods=["POST"])
@admin_required
def delete_booking(booking_id):
    conn = get_connection()
    cursor = conn.cursor()

    archived_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        SELECT service_id, employee_id, booking_date, booking_time
        FROM bookings
        WHERE id = ?
        LIMIT 1
    """, (booking_id,))
    booking_row = cursor.fetchone()

    cursor.execute("""
        UPDATE bookings
        SET
            archived = 1,
            archived_at = ?,
            archived_reason = ?
        WHERE id = ?
    """, (archived_at, "deleted_by_admin", booking_id))

    conn.commit()
    conn.close()

    if booking_row:
        mark_first_waitlist_match_for_slot(
            booking_row["service_id"],
            booking_row["employee_id"],
            booking_row["booking_date"],
            booking_row["booking_time"]
        )

    flash("Rezerwacja została przeniesiona do archiwum.", "success")
    return redirect(url_for("admin_dashboard"))

def has_matching_available_slot(
    service_id,
    employee_id,
    preferred_date_from,
    preferred_date_to,
    preferred_time_from=None,
    preferred_time_to=None,
    end_buffer_minutes=10
):
    if not service_id or not employee_id or not preferred_date_from:
        return False

    def parse_time_to_minutes(value):
        value = (value or "").strip()
        if not value:
            return None

        try:
            hour_str, minute_str = value.split(":")
            return int(hour_str) * 60 + int(minute_str)
        except (ValueError, TypeError):
            return None

    try:
        start_date = datetime.strptime(preferred_date_from, "%Y-%m-%d").date()

        if preferred_date_to:
            end_date = datetime.strptime(preferred_date_to, "%Y-%m-%d").date()
        else:
            end_date = start_date

        if end_date < start_date:
            end_date = start_date

    except ValueError:
        return False

    preferred_time_from_minutes = parse_time_to_minutes(preferred_time_from)
    preferred_time_to_minutes = parse_time_to_minutes(preferred_time_to)

    adjusted_time_to_minutes = preferred_time_to_minutes
    if preferred_time_to_minutes is not None:
        adjusted_time_to_minutes = preferred_time_to_minutes - end_buffer_minutes

        if preferred_time_from_minutes is not None and adjusted_time_to_minutes < preferred_time_from_minutes:
            adjusted_time_to_minutes = preferred_time_from_minutes

    current_date = start_date

    while current_date <= end_date:
        booking_date = current_date.strftime("%Y-%m-%d")
        slots = get_available_slots_for_day(service_id, employee_id, booking_date)

        if slots:
            if preferred_time_from_minutes is not None or adjusted_time_to_minutes is not None:
                for slot in slots:
                    slot_minutes = parse_time_to_minutes(slot)

                    if slot_minutes is None:
                        continue

                    if preferred_time_from_minutes is not None and slot_minutes < preferred_time_from_minutes:
                        continue

                    if adjusted_time_to_minutes is not None and slot_minutes > adjusted_time_to_minutes:
                        continue

                    return True
            else:
                return True

        current_date += timedelta(days=1)

    return False

# =========================================================
# ADMIN SERVICES
# =========================================================

@app.route("/admin/services")
@admin_required
def admin_services():
    conn = get_connection()
    cursor = conn.cursor()

    settings = get_settings()

    cursor.execute("""
        SELECT id, full_name, role, email, active
        FROM employees
        WHERE active = 1
        ORDER BY full_name ASC
    """)
    employees = cursor.fetchall()

    cursor.execute("""
        SELECT id, name, service_group, duration_minutes, price, active
        FROM services
        ORDER BY id ASC
    """)
    service_rows = cursor.fetchall()

    services = []

    for row in service_rows:
        service = dict(row)

        cursor.execute("""
            SELECT e.id, e.full_name
            FROM service_employees se
            JOIN employees e ON e.id = se.employee_id
            WHERE se.service_id = ?
            ORDER BY e.full_name ASC
        """, (row["id"],))

        employee_rows = cursor.fetchall()

        service["employee_names"] = [employee["full_name"] for employee in employee_rows]
        service["employee_ids_csv"] = ",".join(str(employee["id"]) for employee in employee_rows)

        services.append(service)

    conn.close()

    return render_template(
        "admin_services.html",
        page_title="Usługi",
        services=services,
        employees=employees,
        settings=settings
    )


@app.route("/admin/services/add", methods=["POST"])
@admin_required
def add_service():
    name = request.form.get("name", "").strip()
    service_group = request.form.get("service_group", "").strip()
    duration_minutes = request.form.get("duration_minutes", type=int)
    price = request.form.get("price", "").strip()
    employee_ids = request.form.getlist("employee_ids[]")

    if not name:
        flash("Podaj nazwę usługi.", "error")
        return redirect(url_for("admin_services"))

    if not duration_minutes or duration_minutes < 5:
        flash("Podaj poprawny czas trwania usługi.", "error")
        return redirect(url_for("admin_services"))

    if not employee_ids:
        flash("Wybierz co najmniej jednego pracownika dla usługi.", "error")
        return redirect(url_for("admin_services"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO services (name, service_group, duration_minutes, price, active)
            VALUES (?, ?, ?, ?, 1)
        """, (
            name,
            service_group or None,
            duration_minutes,
            price or None
        ))

        service_id = cursor.lastrowid

        for employee_id in employee_ids:
            cursor.execute("""
                INSERT INTO service_employees (service_id, employee_id)
                VALUES (?, ?)
            """, (service_id, employee_id))

        conn.commit()

    except Exception:
        conn.rollback()
        flash("Nie udało się dodać usługi.", "error")
        conn.close()
        return redirect(url_for("admin_services"))

    conn.close()
    return redirect(url_for("admin_services"))


@app.route("/admin/services/<int:service_id>/toggle", methods=["POST"])
@admin_required
def toggle_service(service_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT active FROM services WHERE id = ?", (service_id,))
    service = cursor.fetchone()

    if not service:
        conn.close()
        return jsonify({"success": False, "message": "Usługa nie została znaleziona."}), 404

    new_status = 0 if service["active"] == 1 else 1

    cursor.execute(
        "UPDATE services SET active = ? WHERE id = ?",
        (new_status, service_id)
    )
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "active": new_status,
        "status_label": "Aktywna" if new_status == 1 else "Nieaktywna",
        "button_label": "Wyłącz" if new_status == 1 else "Włącz"
    })


@app.route("/admin/services/<int:service_id>/delete", methods=["POST"])
@admin_required
def delete_service(service_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("DELETE FROM services WHERE id = ?", (service_id,))
        conn.commit()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": True})

        flash("Usługa została usunięta.", "success")
        return redirect(url_for("admin_services"))

    except Exception:
        conn.rollback()

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "Nie udało się usunąć usługi."}), 500

        flash("Nie udało się usunąć usługi.", "error")
        return redirect(url_for("admin_services"))

    finally:
        conn.close()

@app.route("/admin/services/update", methods=["POST"])
@admin_required
def update_service():
    service_id = request.form.get("service_id")
    name = (request.form.get("name") or "").strip()
    service_group = (request.form.get("service_group") or "").strip()
    duration_minutes = (request.form.get("duration_minutes") or "").strip()
    price = (request.form.get("price") or "").strip()
    employee_ids = request.form.getlist("employee_ids[]")

    if not service_id:
        flash("Nie wybrano usługi do edycji.", "error")
        return redirect(url_for("admin_services"))

    if not name:
        flash("Nazwa usługi jest wymagana.", "error")
        return redirect(url_for("admin_services"))

    if not duration_minutes:
        flash("Czas trwania usługi jest wymagany.", "error")
        return redirect(url_for("admin_services"))

    try:
        service_id_int = int(service_id)
        duration_minutes_int = int(duration_minutes)
    except ValueError:
        flash("Nieprawidłowe dane usługi.", "error")
        return redirect(url_for("admin_services"))

    if duration_minutes_int < 5:
        flash("Czas trwania usługi musi wynosić co najmniej 5 minut.", "error")
        return redirect(url_for("admin_services"))

    valid_employee_ids = []
    for employee_id in employee_ids:
        try:
            valid_employee_ids.append(int(employee_id))
        except (TypeError, ValueError):
            continue

    if not valid_employee_ids:
        flash("Wybierz przynajmniej jednego pracownika dla usługi.", "error")
        return redirect(url_for("admin_services"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE services
            SET name = ?, service_group = ?, duration_minutes = ?, price = ?
            WHERE id = ?
            """,
            (
                name,
                service_group or None,
                duration_minutes_int,
                price or None,
                service_id_int
            )
        )

        cursor.execute(
            "DELETE FROM service_employees WHERE service_id = ?",
            (service_id_int,)
        )

        for employee_id in valid_employee_ids:
            cursor.execute(
                """
                INSERT INTO service_employees (service_id, employee_id)
                VALUES (?, ?)
                """,
                (service_id_int, employee_id)
            )

        conn.commit()
        flash("Usługa została zaktualizowana.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd update_service:", e)
        flash("Nie udało się zaktualizować usługi.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_services"))
# =========================================================
# ADMIN SETTINGS
# =========================================================

@app.route("/admin/settings")
@admin_required
def admin_settings():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM business_settings WHERE id = 1")
    settings = cursor.fetchone()

    cursor.execute("SELECT email FROM admins ORDER BY id LIMIT 1")
    admin_row = cursor.fetchone()
    admin_email = admin_row["email"] if admin_row and admin_row["email"] else ""

    cursor.execute("SELECT * FROM employees ORDER BY id DESC")
    employees = cursor.fetchall()

    cursor.execute("SELECT * FROM closed_days ORDER BY closed_date ASC")
    closed_days = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM booking_side_images
        WHERE side = 'left'
        ORDER BY sort_order ASC, id ASC
    """)
    booking_side_images_left = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM booking_side_images
        WHERE side = 'right'
        ORDER BY sort_order ASC, id ASC
    """)
    booking_side_images_right = cursor.fetchall()

    conn.close()

    employee_ids = [employee["id"] for employee in employees]

    employee_schedule_map = build_employee_schedule_map()
    employee_time_off_map = build_employee_time_off_map(employee_ids)
    employee_schedule_exceptions_map = build_employee_schedule_exceptions_map(employee_ids)

    return render_template(
        "admin_settings.html",
        settings=settings,
        admin_email=admin_email,
        employees=employees,
        closed_days=closed_days,
        employee_schedule_map=employee_schedule_map,
        employee_time_off_map=employee_time_off_map,
        employee_schedule_exceptions_map=employee_schedule_exceptions_map,
        booking_side_images_left=booking_side_images_left,
        booking_side_images_right=booking_side_images_right,
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    flash("Ta sekcja jest obecnie wyłączona.", "error")
    return redirect(url_for("admin_login"))

    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not email or not password or not confirm_password:
            flash("Wypełnij wszystkie pola.", "error")
            return render_template(
                "register.html",
                page_title="Rejestracja",
                settings=settings
            )

        if password != confirm_password:
            flash("Hasła nie są takie same.", "error")
            return render_template(
                "register.html",
                page_title="Rejestracja",
                settings=settings
            )

        if len(password) < 8:
            flash("Hasło musi mieć co najmniej 8 znaków.", "error")
            return render_template(
                "register.html",
                page_title="Rejestracja",
                settings=settings
            )

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT id FROM admins WHERE email = ?",
                (email,)
            )
            existing_admin = cursor.fetchone()

            if existing_admin:
                flash("Konto z takim adresem e-mail już istnieje.", "error")
                return render_template(
                    "register.html",
                    page_title="Rejestracja",
                    settings=settings
                )

            password_hash = generate_password_hash(password)
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            cursor.execute("""
                INSERT INTO admins (email, password_hash, full_name, is_active, created_at)
                VALUES (?, ?, ?, 1, ?)
            """, (
                email,
                password_hash,
                full_name,
                created_at
            ))

            conn.commit()
            flash("Konto zostało utworzone. Możesz się zalogować.", "success")
            return redirect(url_for("admin_login"))

        except Exception:
            conn.rollback()
            flash("Nie udało się utworzyć konta.", "error")
            return render_template(
                "register.html",
                page_title="Rejestracja",
                settings=settings
            )

        finally:
            conn.close()

    return render_template(
        "register.html",
        page_title="Rejestracja",
        settings=settings
    )

@app.route("/admin/settings/employees/add", methods=["POST"])
@admin_required
def add_employee():
    full_name = request.form.get("employee_name", "").strip()
    role = request.form.get("employee_role", "").strip()
    email = request.form.get("employee_email", "").strip()

    photo = request.files.get("employee_photo")
    photo_path = None

    if not full_name:
        flash("Podaj imię i nazwisko pracownika.", "error")
        return redirect(url_for("admin_settings"))

    if photo and photo.filename:
        os.makedirs(UPLOAD_EMPLOYEES_DIR, exist_ok=True)

        safe_name = secure_filename(photo.filename)
        normalized_name = "_".join(full_name.lower().split())
        filename = f"{normalized_name}_{safe_name}"
        save_path = os.path.join(UPLOAD_EMPLOYEES_DIR, filename)

        photo.save(save_path)
        photo_path = os.path.join("images", filename).replace("\\", "/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO employees (full_name, role, email, photo_path, active)
        VALUES (?, ?, ?, ?, 1)
    """, (full_name, role or None, email or None, photo_path))

    conn.commit()
    conn.close()

    flash("Pracownik został dodany.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/employees/<int:employee_id>/delete", methods=["POST"])
@admin_required
def delete_employee(employee_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT photo_path
            FROM employees
            WHERE id = ?
            LIMIT 1
            """,
            (employee_id,)
        )
        employee = cursor.fetchone()

        if not employee:
            flash("Nie znaleziono pracownika.", "error")
            return redirect(url_for("admin_settings"))

        photo_path = employee["photo_path"] if employee["photo_path"] else None

        cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id,))
        conn.commit()

        delete_static_file(photo_path)

        flash("Pracownik został usunięty.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_employee:", e)
        flash("Nie udało się usunąć pracownika.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/employees/update-schedule", methods=["POST"])
@admin_required
def update_employee_schedule():
    employee_id = request.form.get("employee_id", type=int)
    time_off_action = (request.form.get("time_off_action") or "save_schedule").strip()

    if not employee_id:
        flash("Nie znaleziono pracownika.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    weekday_keys = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]

    try:
        if time_off_action == "save_schedule":
            import base64
            import uuid

            employee_name = (request.form.get("employee_name") or "").strip()
            active_value = request.form.get("active", "1")
            active = 1 if str(active_value) == "1" else 0

            remove_employee_photo = (request.form.get("remove_employee_photo") or "0").strip()
            cropped_employee_photo_data = (request.form.get("cropped_employee_photo_data") or "").strip()
            photo_file = request.files.get("employee_photo")

            if not employee_name:
                flash("Podaj imię i nazwisko pracownika.", "error")
                return redirect(url_for("admin_settings"))

            cursor.execute(
                """
                SELECT photo_path
                FROM employees
                WHERE id = ?
                LIMIT 1
                """,
                (employee_id,)
            )
            employee_row = cursor.fetchone()

            if not employee_row:
                flash("Nie znaleziono pracownika.", "error")
                return redirect(url_for("admin_settings"))

            old_photo_path = employee_row["photo_path"] if employee_row["photo_path"] else None

            cursor.execute(
                """
                UPDATE employees
                SET full_name = ?, active = ?
                WHERE id = ?
                """,
                (employee_name, active, employee_id)
            )

            upload_dir = os.path.join(app.static_folder, "images")
            os.makedirs(upload_dir, exist_ok=True)

            if cropped_employee_photo_data:
                try:
                    if "," not in cropped_employee_photo_data:
                        raise ValueError("Nieprawidłowe dane obrazu.")

                    header, encoded = cropped_employee_photo_data.split(",", 1)

                    if "image/png" in header:
                        extension = ".png"
                    elif "image/jpeg" in header or "image/jpg" in header:
                        extension = ".jpg"
                    elif "image/webp" in header:
                        extension = ".webp"
                    else:
                        extension = ".png"

                    new_filename = f"employee_{employee_id}_{uuid.uuid4().hex}{extension}"
                    save_path = os.path.join(upload_dir, new_filename)

                    with open(save_path, "wb") as image_file:
                        image_file.write(base64.b64decode(encoded))

                    new_photo_path = f"images/{new_filename}"

                    cursor.execute(
                        """
                        UPDATE employees
                        SET photo_path = ?
                        WHERE id = ?
                        """,
                        (new_photo_path, employee_id)
                    )

                    if old_photo_path and old_photo_path != new_photo_path:
                        delete_static_file(old_photo_path)

                except Exception as e:
                    print("Błąd zapisu przyciętego zdjęcia:", e)
                    flash("Nie udało się zapisać przyciętego zdjęcia.", "error")
                    return redirect(url_for("admin_settings"))

            elif remove_employee_photo == "1":
                cursor.execute(
                    """
                    UPDATE employees
                    SET photo_path = NULL
                    WHERE id = ?
                    """,
                    (employee_id,)
                )

                if old_photo_path:
                    delete_static_file(old_photo_path)

            elif photo_file and photo_file.filename:
                original_filename = secure_filename(photo_file.filename)
                _, extension = os.path.splitext(original_filename)
                extension = extension.lower()

                allowed_extensions = {".png", ".jpg", ".jpeg", ".webp"}

                if extension not in allowed_extensions:
                    flash("Dozwolone formaty zdjęcia to: PNG, JPG, JPEG, WEBP.", "error")
                    return redirect(url_for("admin_settings"))

                new_filename = f"employee_{employee_id}_{uuid.uuid4().hex}{extension}"
                save_path = os.path.join(upload_dir, new_filename)

                photo_file.save(save_path)
                new_photo_path = f"images/{new_filename}"

                cursor.execute(
                    """
                    UPDATE employees
                    SET photo_path = ?
                    WHERE id = ?
                    """,
                    (new_photo_path, employee_id)
                )

                if old_photo_path and old_photo_path != new_photo_path:
                    delete_static_file(old_photo_path)

            cursor.execute(
                """
                DELETE FROM employee_work_schedule
                WHERE employee_id = ?
                """,
                (employee_id,)
            )

            for day_key in weekday_keys:
                enabled = 1 if request.form.get(f"{day_key}_enabled") else 0
                start_time = (request.form.get(f"{day_key}_start") or "").strip()
                end_time = (request.form.get(f"{day_key}_end") or "").strip()

                if enabled:
                    cursor.execute(
                        """
                        INSERT INTO employee_work_schedule (
                            employee_id,
                            day_key,
                            enabled,
                            start_time,
                            end_time
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            employee_id,
                            day_key,
                            1,
                            start_time or None,
                            end_time or None
                        )
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO employee_work_schedule (
                            employee_id,
                            day_key,
                            enabled,
                            start_time,
                            end_time
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (employee_id, day_key, 0, None, None)
                    )

            conn.commit()
            flash("Zapisano dane pracownika.", "success")

        elif time_off_action == "add_vacation":
            date_from = (request.form.get("vacation_date_from") or "").strip()
            date_to = (request.form.get("vacation_date_to") or "").strip()
            note = (request.form.get("vacation_note") or "").strip()

            if not date_from or not date_to:
                flash("Podaj zakres dat dla urlopu.", "error")
            else:
                cursor.execute(
                    """
                    INSERT INTO employee_time_off (
                        employee_id,
                        type,
                        date_from,
                        date_to,
                        note
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (employee_id, "vacation", date_from, date_to, note or None)
                )
                conn.commit()
                flash("Dodano urlop pracownika.", "success")

        elif time_off_action == "add_sick_leave":
            date_from = (request.form.get("sick_date_from") or "").strip()
            date_to = (request.form.get("sick_date_to") or "").strip()
            note = (request.form.get("sick_note") or "").strip()

            if not date_from or not date_to:
                flash("Podaj zakres dat dla chorobowego.", "error")
            else:
                cursor.execute(
                    """
                    INSERT INTO employee_time_off (
                        employee_id,
                        type,
                        date_from,
                        date_to,
                        note
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (employee_id, "sick_leave", date_from, date_to, note or None)
                )
                conn.commit()
                flash("Dodano chorobowe pracownika.", "success")

        elif time_off_action == "delete_vacation":
            delete_id = request.form.get("delete_vacation_id", type=int)

            if delete_id:
                cursor.execute(
                    """
                    DELETE FROM employee_time_off
                    WHERE id = ? AND employee_id = ? AND type = ?
                    """,
                    (delete_id, employee_id, "vacation")
                )
                conn.commit()
                flash("Usunięto urlop.", "success")

        elif time_off_action == "delete_sick_leave":
            delete_id = request.form.get("delete_sick_leave_id", type=int)

            if delete_id:
                cursor.execute(
                    """
                    DELETE FROM employee_time_off
                    WHERE id = ? AND employee_id = ? AND type = ?
                    """,
                    (delete_id, employee_id, "sick_leave")
                )
                conn.commit()
                flash("Usunięto chorobowe.", "success")

        elif time_off_action == "add_schedule_exception":
            exception_date = (request.form.get("exception_date") or "").strip()
            exception_type = (request.form.get("exception_type") or "").strip()
            exception_start_time = (request.form.get("exception_start_time") or "").strip()
            exception_end_time = (request.form.get("exception_end_time") or "").strip()
            exception_note = (request.form.get("exception_note") or "").strip()

            if not exception_date:
                flash("Podaj datę wyjątkowego dnia.", "error")

            elif exception_type not in ["custom_hours", "day_off"]:
                flash("Nieprawidłowy rodzaj wyjątku.", "error")

            elif exception_type == "custom_hours" and (not exception_start_time or not exception_end_time):
                flash("Podaj godziny dla niestandardowego dnia pracy.", "error")

            else:
                is_day_off = 1 if exception_type == "day_off" else 0
                start_time = None if is_day_off else exception_start_time
                end_time = None if is_day_off else exception_end_time

                cursor.execute(
                    """
                    INSERT INTO employee_schedule_exceptions (
                        employee_id,
                        exception_date,
                        is_day_off,
                        start_time,
                        end_time,
                        note
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(employee_id, exception_date)
                    DO UPDATE SET
                        is_day_off = excluded.is_day_off,
                        start_time = excluded.start_time,
                        end_time = excluded.end_time,
                        note = excluded.note
                    """,
                    (
                        employee_id,
                        exception_date,
                        is_day_off,
                        start_time,
                        end_time,
                        exception_note or None
                    )
                )
                conn.commit()
                flash("Zapisano wyjątkowy dzień pracy.", "success")

        elif time_off_action == "delete_schedule_exception":
            delete_id = request.form.get("delete_schedule_exception_id", type=int)

            if delete_id:
                cursor.execute(
                    """
                    DELETE FROM employee_schedule_exceptions
                    WHERE id = ? AND employee_id = ?
                    """,
                    (delete_id, employee_id)
                )
                conn.commit()
                flash("Usunięto wyjątkowy dzień.", "success")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))



@app.route("/admin/settings/update", methods=["POST"])
@admin_required
def update_settings():
    company_name = (request.form.get("company_name") or "").strip()
    company_address = (request.form.get("company_address") or "").strip()
    contact_phone = (request.form.get("contact_phone") or "").strip()
    contact_email = (request.form.get("contact_email") or "").strip()
    primary_color = (request.form.get("primary_color") or "").strip()

    slot_interval_minutes = request.form.get("slot_interval_minutes", type=int)
    logo_width = request.form.get("logo_width", type=int)
    logo_height = request.form.get("logo_height", type=int)
    company_name_size = request.form.get("company_name_size", type=int)
    logo_text_gap = request.form.get("logo_text_gap", type=int)

    if not company_name or not primary_color or not slot_interval_minutes:
        flash("Proszę uzupełnić wszystkie wymagane ustawienia.", "error")
        return redirect(url_for("admin_settings"))

    if logo_width is None:
        logo_width = 120

    if logo_height is None:
        logo_height = 44

    if company_name_size is None:
        company_name_size = 22

    if logo_text_gap is None:
        logo_text_gap = 12

    logo_width = max(40, min(260, logo_width))
    logo_height = max(20, min(120, logo_height))
    company_name_size = max(12, min(42, company_name_size))
    logo_text_gap = max(0, min(40, logo_text_gap))
    slot_interval_minutes = max(5, min(180, slot_interval_minutes))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT logo_path FROM business_settings WHERE id = 1")
        current_settings = cursor.fetchone()
        current_logo_path = current_settings["logo_path"] if current_settings else None

        logo_file = request.files.get("logo_file")
        logo_path = current_logo_path

        if logo_file and logo_file.filename:
            upload_folder = os.path.join(app.static_folder, "uploads", "logos")
            os.makedirs(upload_folder, exist_ok=True)

            safe_name = secure_filename(logo_file.filename)
            filename = f"company_logo_{safe_name}"
            save_path = os.path.join(upload_folder, filename)

            logo_file.save(save_path)
            logo_path = f"uploads/logos/{filename}"

        cursor.execute("""
            INSERT OR IGNORE INTO business_settings (
                id,
                company_name,
                company_address,
                contact_phone,
                primary_color,
                contact_email,
                slot_interval_minutes,
                logo_path,
                logo_width,
                logo_height,
                company_name_size,
                logo_text_gap
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            1,
            "Booking System",
            "",
            "",
            "#1f3c88",
            "kontakt@example.com",
            30,
            None,
            120,
            44,
            22,
            12
        ))

        cursor.execute(
            """
            UPDATE business_settings
            SET
                company_name = ?,
                company_address = ?,
                contact_phone = ?,
                primary_color = ?,
                contact_email = ?,
                slot_interval_minutes = ?,
                logo_path = ?,
                logo_width = ?,
                logo_height = ?,
                company_name_size = ?,
                logo_text_gap = ?
            WHERE id = 1
            """,
            (
                company_name,
                company_address,
                contact_phone,
                primary_color,
                contact_email,
                slot_interval_minutes,
                logo_path,
                logo_width,
                logo_height,
                company_name_size,
                logo_text_gap,
            )
        )

        conn.commit()
    finally:
        conn.close()

    flash("Ustawienia zostały zapisane.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/delete-logo", methods=["POST"])
@admin_required
def delete_logo():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT logo_path FROM business_settings WHERE id = 1")
    settings = cursor.fetchone()

    if settings and settings["logo_path"]:
        file_path = os.path.join(app.static_folder, settings["logo_path"])

        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

        cursor.execute("""
            UPDATE business_settings
            SET logo_path = NULL
            WHERE id = 1
        """)
        conn.commit()

    conn.close()

    flash("Logo zostało usunięte.", "success")
    return redirect(url_for("admin_settings"))


# =========================================================
# CLOSED DAYS
# =========================================================

@app.route("/admin/closed-days/add", methods=["POST"])
@admin_required
def add_closed_day():
    closed_date = request.form.get("closed_date", "").strip()
    note = request.form.get("note", "").strip()

    if not closed_date:
        flash("Data wyłączenia jest wymagana.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO closed_days (closed_date, note)
            VALUES (?, ?)
        """, (closed_date, note))
        conn.commit()
        flash("Dzień wyłączony został dodany.", "success")
    except Exception:
        flash("Taki dzień wyłączony już istnieje.", "error")
    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/closed-days/<int:closed_day_id>/delete", methods=["POST"])
@admin_required
def delete_closed_day(closed_day_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM closed_days WHERE id = ?", (closed_day_id,))
    conn.commit()
    conn.close()

    flash("Dzień wyłączony został usunięty.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/bookings/<int:booking_id>/delete-archived", methods=["POST"])
@admin_required
def delete_archived_booking(booking_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM bookings
        WHERE id = ?
          AND COALESCE(archived, 0) = 1
    """, (booking_id,))

    conn.commit()
    conn.close()

    flash("Rezerwacja została trwale usunięta z archiwum.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bookings/report")
@admin_required
def bookings_report():
    client_name = (request.args.get("client_name") or "").strip()
    employee_id = (request.args.get("employee_id") or "").strip()
    date_from = (request.args.get("date_from") or "").strip()
    date_to = (request.args.get("date_to") or "").strip()
    scope = (request.args.get("scope") or "all").strip().lower()

    if scope not in {"all", "active", "archive"}:
        scope = "all"

    conn = get_connection()
    cursor = conn.cursor()

    settings = get_settings()

    employee_name = ""
    if employee_id:
        try:
            employee_id_int = int(employee_id)
            cursor.execute("""
                SELECT full_name
                FROM employees
                WHERE id = ?
                LIMIT 1
            """, (employee_id_int,))
            employee_row = cursor.fetchone()
            if employee_row:
                employee_name = employee_row["full_name"] or ""
        except (ValueError, TypeError):
            employee_id = ""
            employee_name = ""

    query = """
        SELECT
            bookings.id,
            bookings.client_name,
            bookings.client_email,
            bookings.client_phone,
            bookings.booking_date,
            bookings.booking_time,
            bookings.notes,
            bookings.status,
            bookings.archived,
            bookings.employee_id,
            services.name AS service_name,
            employees.full_name AS employee_name
        FROM bookings
        LEFT JOIN services ON bookings.service_id = services.id
        LEFT JOIN employees ON bookings.employee_id = employees.id
        WHERE 1 = 1
    """

    params = []

    if scope == "active":
        query += " AND COALESCE(bookings.archived, 0) = 0"
    elif scope == "archive":
        query += " AND COALESCE(bookings.archived, 0) = 1"

    if client_name:
        query += " AND LOWER(COALESCE(bookings.client_name, '')) LIKE ?"
        params.append(f"%{client_name.lower()}%")

    if employee_id:
        try:
            employee_id_int = int(employee_id)
            query += " AND bookings.employee_id = ?"
            params.append(employee_id_int)
        except (ValueError, TypeError):
            pass

    if date_from:
        query += " AND bookings.booking_date >= ?"
        params.append(date_from)

    if date_to:
        query += " AND bookings.booking_date <= ?"
        params.append(date_to)

    query += """
        ORDER BY
            bookings.booking_date ASC,
            bookings.booking_time ASC,
            bookings.id ASC
    """

    cursor.execute(query, params)
    report_items = cursor.fetchall()

    conn.close()

    return render_template(
        "bookings_report.html",
        page_title="Raport wizyt",
        settings=settings,
        report_items=report_items,
        report_filters={
            "client_name": client_name,
            "employee_id": employee_id,
            "employee_name": employee_name,
            "date_from": date_from,
            "date_to": date_to,
            "scope": scope,
        }
    )


@app.route("/admin/settings/update-admin-email", methods=["POST"])
@admin_required
def update_admin_email():
    new_email = (request.form.get("admin_email") or "").strip().lower()

    if not new_email:
        flash("Podaj adres e-mail administratora.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM admins ORDER BY id LIMIT 1")
        admin = cursor.fetchone()

        if not admin:
            flash("Nie znaleziono konta administratora.", "error")
            conn.close()
            return redirect(url_for("admin_settings"))

        cursor.execute(
            """
            UPDATE admins
            SET email = ?
            WHERE id = ?
            """,
            (new_email, admin["id"])
        )
        conn.commit()
        flash("Adres e-mail administratora został zaktualizowany.", "success")

    except Exception:
        conn.rollback()
        flash("Nie udało się zaktualizować adresu e-mail administratora.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/api/manual-booking-slots")
@admin_required
def admin_manual_booking_slots():
    booking_date = (request.args.get("booking_date") or "").strip()

    if not booking_date:
        return jsonify({"slots": []})

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                s.id AS service_id,
                s.name AS service_name,
                s.duration_minutes,
                s.price,
                e.id AS employee_id,
                e.full_name AS employee_name,
                e.role AS employee_role
            FROM services s
            JOIN service_employees se ON se.service_id = s.id
            JOIN employees e ON e.id = se.employee_id
            WHERE s.active = 1
              AND e.active = 1
            ORDER BY e.full_name ASC, s.name ASC
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()

    slots_output = []

    for row in rows:
        service_id = row["service_id"]
        employee_id = row["employee_id"]

        try:
            slots = get_available_slots_for_day(service_id, employee_id, booking_date)
        except Exception:
            slots = []

        for slot_time in slots:
            slots_output.append({
                "service_id": service_id,
                "service_name": row["service_name"],
                "duration_minutes": row["duration_minutes"],
                "price": row["price"] or "",
                "employee_id": employee_id,
                "employee_name": row["employee_name"],
                "employee_role": row["employee_role"] or "",
                "booking_date": booking_date,
                "booking_time": slot_time
            })

    slots_output.sort(
        key=lambda item: (
            item["booking_time"],
            item["employee_name"].lower(),
            item["service_name"].lower()
        )
    )

    return jsonify({"slots": slots_output})


@app.route("/admin/bookings/create-manual", methods=["POST"])
@admin_required
def create_manual_booking():
    service_mode = (request.form.get("service_mode") or "list").strip()

    service_id = request.form.get("service_id", type=int)
    employee_id = request.form.get("employee_id", type=int)
    custom_employee_id = request.form.get("custom_employee_id", type=int)

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()
    booking_date = (request.form.get("booking_date") or "").strip()
    booking_time = (request.form.get("booking_time") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    custom_service_name = (request.form.get("custom_service_name") or "").strip()
    custom_duration_minutes = request.form.get("custom_duration_minutes", type=int)
    custom_price = (request.form.get("custom_price") or "").strip()

    privacy_consent = 0
    marketing_consent = 0
    consents_created_at = None

    if not client_name or not client_phone or not booking_date or not booking_time:
        flash("Uzupełnij wymagane dane ręcznej rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    created_custom_service = False
    final_service_id = service_id

    try:
        if service_mode == "custom":
            employee_id = custom_employee_id or employee_id

            if not employee_id:
                flash("Wybierz pracownika dla usługi niestandardowej.", "error")
                return redirect(url_for("admin_dashboard"))

            if not custom_service_name or not custom_duration_minutes:
                flash("Dla usługi niestandardowej podaj nazwę i czas trwania.", "error")
                return redirect(url_for("admin_dashboard"))

            cursor.execute(
                """
                INSERT INTO services (name, service_group, duration_minutes, price, active)
                VALUES (?, ?, ?, ?, 1)
                """,
                (
                    custom_service_name,
                    "Niestandardowe",
                    custom_duration_minutes,
                    custom_price or None
                )
            )
            final_service_id = cursor.lastrowid

            cursor.execute(
                """
                INSERT INTO service_employees (service_id, employee_id)
                VALUES (?, ?)
                """,
                (final_service_id, employee_id)
            )

            conn.commit()
            created_custom_service = True

        else:
            if not employee_id:
                flash("Wybierz pracownika.", "error")
                return redirect(url_for("admin_dashboard"))

            if not final_service_id:
                flash("Nie wybrano usługi.", "error")
                return redirect(url_for("admin_dashboard"))

        available_slots = get_available_slots_for_day(final_service_id, employee_id, booking_date)

        if booking_time not in available_slots:
            if service_mode == "custom" and created_custom_service:
                cleanup_conn = get_connection()
                cleanup_cursor = cleanup_conn.cursor()

                try:
                    cleanup_cursor.execute(
                        "DELETE FROM service_employees WHERE service_id = ?",
                        (final_service_id,)
                    )
                    cleanup_cursor.execute(
                        "DELETE FROM services WHERE id = ?",
                        (final_service_id,)
                    )
                    cleanup_conn.commit()
                finally:
                    cleanup_conn.close()

            flash("Wybrany termin nie jest już dostępny.", "error")
            return redirect(url_for("admin_dashboard"))

        client_id = get_or_create_client(
            full_name=client_name,
            phone=client_phone,
            email=client_email,
            privacy_consent=privacy_consent,
            marketing_consent=marketing_consent,
            consent_source=None,
            consent_timestamp=None
        )

        if not client_id:
            if service_mode == "custom" and created_custom_service:
                cleanup_conn = get_connection()
                cleanup_cursor = cleanup_conn.cursor()

                try:
                    cleanup_cursor.execute(
                        "DELETE FROM service_employees WHERE service_id = ?",
                        (final_service_id,)
                    )
                    cleanup_cursor.execute(
                        "DELETE FROM services WHERE id = ?",
                        (final_service_id,)
                    )
                    cleanup_conn.commit()
                finally:
                    cleanup_conn.close()

            flash("Nie udało się utworzyć lub odnaleźć karty klienta.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            INSERT INTO bookings (
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email,
                client_phone,
                booking_date,
                booking_time,
                notes,
                status,
                privacy_consent,
                marketing_consent,
                consents_created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                final_service_id,
                employee_id,
                client_id,
                client_name,
                client_email or None,
                client_phone,
                booking_date,
                booking_time,
                notes or None,
                "confirmed",
                privacy_consent,
                marketing_consent,
                consents_created_at
            )
        )

        conn.commit()
        flash("Ręczna rezerwacja została zapisana.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd create_manual_booking:", e)
        flash("Nie udało się zapisać ręcznej rezerwacji.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/waitlist/<int:waitlist_entry_id>/book", methods=["POST"])
@admin_required
def create_booking_from_waitlist(waitlist_entry_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM waitlist_entries
            WHERE id = ?
            LIMIT 1
            """,
            (waitlist_entry_id,)
        )
        waitlist_row = cursor.fetchone()

        if not waitlist_row:
            flash("Nie znaleziono wpisu na liście oczekujących.", "error")
            return redirect(url_for("admin_dashboard"))

        waitlist_status = (waitlist_row["status"] or "").strip().lower()
        if waitlist_status != "matched":
            flash("Ten wpis nie jest jeszcze dopasowany do zwolnionego terminu.", "error")
            return redirect(url_for("admin_dashboard"))

        service_id = waitlist_row["service_id"]
        employee_id = waitlist_row["employee_id"]
        booking_date = (waitlist_row["matched_booking_date"] or "").strip()
        booking_time = (waitlist_row["matched_booking_time"] or "").strip()

        if not service_id or not employee_id or not booking_date or not booking_time:
            flash("Brakuje danych dopasowanego terminu.", "error")
            return redirect(url_for("admin_dashboard"))

        available_slots = get_available_slots_for_day(service_id, employee_id, booking_date)

        if booking_time not in available_slots:
            conn.close()
            clear_waitlist_match(waitlist_entry_id)
            flash("Ten termin nie jest już dostępny. Wpis wrócił do oczekujących.", "error")
            return redirect(url_for("admin_dashboard"))

        client_id = get_or_create_client(
            full_name=waitlist_row["client_name"] or "",
            phone=waitlist_row["client_phone"] or "",
            email=waitlist_row["client_email"] or ""
        )

        if not client_id:
            flash("Nie udało się utworzyć lub odnaleźć karty klienta.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            INSERT INTO bookings (
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email,
                client_phone,
                booking_date,
                booking_time,
                notes,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                employee_id,
                client_id,
                waitlist_row["client_name"],
                waitlist_row["client_email"] or None,
                waitlist_row["client_phone"] or None,
                booking_date,
                booking_time,
                waitlist_row["notes"] or None,
                "new"
            )
        )

        cursor.execute(
            """
            UPDATE waitlist_entries
            SET status = 'booked'
            WHERE id = ?
            """,
            (waitlist_entry_id,)
        )

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd create_booking_from_waitlist:", e)
        flash("Nie udało się utworzyć rezerwacji z listy oczekujących.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        try:
            conn.close()
        except Exception:
            pass

    flash("Utworzono rezerwację z listy oczekujących.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/waitlist", methods=["POST"])
def create_waitlist_entry():
    service_id = request.form.get("service_id", type=int)
    employee_id = request.form.get("employee_id", type=int)

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()

    preferred_date_from = (request.form.get("preferred_date_from") or "").strip()
    preferred_date_to = (request.form.get("preferred_date_to") or "").strip()
    preferred_time_from = (request.form.get("preferred_time_from") or "").strip()
    preferred_time_to = (request.form.get("preferred_time_to") or "").strip()

    notes = (request.form.get("notes") or "").strip()

    if not service_id or not employee_id or not client_name:
        flash("Uzupełnij wymagane dane listy oczekujących.", "error")
        return redirect(url_for("booking"))

    if not preferred_date_from:
        flash("Wybierz datę początkową dla listy oczekujących.", "error")
        return redirect(url_for("booking"))

    if has_matching_available_slot(
        service_id=service_id,
        employee_id=employee_id,
        preferred_date_from=preferred_date_from,
        preferred_date_to=preferred_date_to,
        preferred_time_from=preferred_time_from,
        preferred_time_to=preferred_time_to
    ):
        session["waitlist_redirect_context"] = {
            "service_id": service_id,
            "employee_id": employee_id,
            "client_name": client_name,
            "client_email": client_email,
            "client_phone": client_phone,
            "preferred_date_from": preferred_date_from,
            "preferred_date_to": preferred_date_to,
            "preferred_time_from": preferred_time_from,
            "preferred_time_to": preferred_time_to,
            "notes": notes,
            "reason": "slots_available"
        }

        flash(
            "Dla wybranych preferencji są już dostępne wolne terminy. Nie dodaliśmy wpisu do listy oczekujących — możesz od razu zarezerwować wizytę poniżej.",
            "info"
        )
        return redirect(url_for("booking", open_slots="1"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO waitlist_entries (
                service_id,
                employee_id,
                client_name,
                client_email,
                client_phone,
                preferred_date_from,
                preferred_date_to,
                preferred_time_from,
                preferred_time_to,
                notes,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                service_id,
                employee_id,
                client_name,
                client_email or None,
                client_phone or None,
                preferred_date_from or None,
                preferred_date_to or None,
                preferred_time_from or None,
                preferred_time_to or None,
                notes or None,
                "waiting"
            )
        )
        conn.commit()
        flash("Zapisano zgłoszenie do listy oczekujących.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd create_waitlist_entry:", e)
        flash("Nie udało się zapisać zgłoszenia do listy oczekujących.", "error")

    finally:
        conn.close()

    return redirect(url_for("booking"))


@app.route("/admin/waitlist/<int:waitlist_entry_id>/delete", methods=["POST"])
@admin_required
def delete_waitlist_entry(waitlist_entry_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id
            FROM waitlist_entries
            WHERE id = ?
            LIMIT 1
        """, (waitlist_entry_id,))
        row = cursor.fetchone()

        if not row:
            flash("Nie znaleziono wpisu listy oczekujących.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor.execute("""
            DELETE FROM waitlist_entries
            WHERE id = ?
        """, (waitlist_entry_id,))

        conn.commit()
        flash("Usunięto wpis z listy oczekujących.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_waitlist_entry:", e)
        flash("Nie udało się usunąć wpisu z listy oczekujących.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bookings/<int:booking_id>/update", methods=["POST"])
@admin_required
def update_booking(booking_id):
    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()
    status = (request.form.get("status") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    allowed_statuses = ["new", "confirmed", "cancelled"]

    if not client_name:
        flash("Podaj imię i nazwisko klienta.", "error")
        return redirect(url_for("admin_dashboard"))

    if status not in allowed_statuses:
        flash("Nieprawidłowy status rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT client_id, service_id, employee_id, booking_date, booking_time, status
            FROM bookings
            WHERE id = ?
            LIMIT 1
        """, (booking_id,))
        booking_row = cursor.fetchone()

        if not booking_row:
            flash("Nie znaleziono rezerwacji.", "error")
            return redirect(url_for("admin_dashboard"))

        previous_status = (booking_row["status"] or "").strip().lower()

        cursor.execute("""
            UPDATE bookings
            SET
                client_name = ?,
                client_email = ?,
                client_phone = ?,
                status = ?,
                notes = ?
            WHERE id = ?
        """, (
            client_name,
            client_email or None,
            client_phone or None,
            status,
            notes or None,
            booking_id
        ))

        if booking_row["client_id"]:
            cursor.execute("""
                UPDATE clients
                SET
                    full_name = ?,
                    phone = ?,
                    email = ?,
                    updated_at = ?
                WHERE id = ?
            """, (
                client_name,
                client_phone or None,
                client_email or None,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                booking_row["client_id"]
            ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd update_booking:", e)
        flash("Nie udało się zaktualizować rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()

    if status == "cancelled" and previous_status != "cancelled":
        mark_first_waitlist_match_for_slot(
            booking_row["service_id"],
            booking_row["employee_id"],
            booking_row["booking_date"],
            booking_row["booking_time"]
        )

    flash("Rezerwacja została zaktualizowana.", "success")
    return redirect(url_for("admin_dashboard"))



@app.route("/admin/clients")
@admin_required
def admin_clients():
    conn = get_connection()
    cursor = conn.cursor()

    settings = get_settings()

    cursor.execute("""
        SELECT
            c.id,
            c.full_name,
            c.phone,
            c.email,
            c.client_status,
            c.notes,
            c.created_at,
            c.updated_at,
            c.preferred_employee_id,
            COUNT(b.id) AS total_bookings,
            MAX(
                CASE
                    WHEN b.booking_date IS NOT NULL AND b.booking_time IS NOT NULL
                    THEN b.booking_date || ' ' || b.booking_time
                    ELSE b.booking_date
                END
            ) AS last_booking_at
        FROM clients c
        LEFT JOIN bookings b ON b.client_id = c.id
        GROUP BY
            c.id,
            c.full_name,
            c.phone,
            c.email,
            c.client_status,
            c.notes,
            c.created_at,
            c.updated_at,
            c.preferred_employee_id
        ORDER BY c.id DESC
    """)
    clients = cursor.fetchall()

    cursor.execute("""
        SELECT
            id,
            full_name
        FROM employees
        WHERE active = 1
        ORDER BY full_name ASC
    """)
    employee_rows = cursor.fetchall()

    employees = [
        {
            "id": row["id"],
            "full_name": row["full_name"]
        }
        for row in employee_rows
    ]

    conn.close()

    return render_template(
        "admin_clients.html",
        page_title="Klienci",
        settings=settings,
        clients=clients,
        employees=employees
    )


@app.route("/admin/clients/<int:client_id>/update", methods=["POST"])
@admin_required
def update_client(client_id):
    full_name = (request.form.get("full_name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip()
    client_status = (request.form.get("client_status") or "standard").strip().lower()
    notes = (request.form.get("notes") or "").strip()
    preferred_employee_id_raw = (request.form.get("preferred_employee_id") or "").strip()

    privacy_consent = 1 if request.form.get("privacy_consent") == "1" else 0
    marketing_consent = 1 if request.form.get("marketing_consent") == "1" else 0

    allowed_statuses = {"standard", "new", "regular", "inactive"}

    if not full_name:
        flash("Podaj imię i nazwisko klienta.", "error")
        return redirect(url_for("admin_clients"))

    if client_status not in allowed_statuses:
        flash("Nieprawidłowy status klienta.", "error")
        return redirect(url_for("admin_clients"))

    preferred_employee_id = None
    if preferred_employee_id_raw:
        try:
            preferred_employee_id = int(preferred_employee_id_raw)
        except ValueError:
            flash("Nieprawidłowy preferowany specjalista.", "error")
            return redirect(url_for("admin_clients"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                privacy_consent,
                privacy_consent_at,
                marketing_consent,
                marketing_consent_at,
                consent_source
            FROM clients
            WHERE id = ?
            LIMIT 1
            """,
            (client_id,)
        )
        existing_client = cursor.fetchone()

        if not existing_client:
            flash("Nie znaleziono klienta.", "error")
            return redirect(url_for("admin_clients"))

        if preferred_employee_id is not None:
            cursor.execute(
                """
                SELECT id
                FROM employees
                WHERE id = ? AND active = 1
                LIMIT 1
                """,
                (preferred_employee_id,)
            )
            employee_row = cursor.fetchone()

            if not employee_row:
                flash("Wybrany specjalista nie istnieje lub jest nieaktywny.", "error")
                return redirect(url_for("admin_clients"))

        updated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        current_privacy_consent = int(existing_client["privacy_consent"] or 0)
        current_privacy_consent_at = existing_client["privacy_consent_at"]

        current_marketing_consent = int(existing_client["marketing_consent"] or 0)
        current_marketing_consent_at = existing_client["marketing_consent_at"]

        current_consent_source = existing_client["consent_source"]

        new_privacy_consent_at = current_privacy_consent_at
        new_marketing_consent_at = current_marketing_consent_at
        new_consent_source = current_consent_source

        if privacy_consent == 1 and current_privacy_consent == 0:
            new_privacy_consent_at = updated_at
            new_consent_source = "admin_manual"

        if marketing_consent == 1 and current_marketing_consent == 0:
            new_marketing_consent_at = updated_at
            new_consent_source = "admin_manual"

        cursor.execute(
            """
            UPDATE clients
            SET
                full_name = ?,
                phone = ?,
                email = ?,
                client_status = ?,
                notes = ?,
                preferred_employee_id = ?,
                privacy_consent = ?,
                privacy_consent_at = ?,
                marketing_consent = ?,
                marketing_consent_at = ?,
                consent_source = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                full_name,
                phone or None,
                email or None,
                client_status,
                notes or None,
                preferred_employee_id,
                privacy_consent,
                new_privacy_consent_at,
                marketing_consent,
                new_marketing_consent_at,
                new_consent_source,
                updated_at,
                client_id
            )
        )

        conn.commit()
        flash("Karta klienta została zaktualizowana.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd update_client:", e)
        flash("Nie udało się zaktualizować karty klienta.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_clients"))


@app.route("/admin/clients/<int:client_id>/delete", methods=["POST"])
@admin_required
def delete_client(client_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM clients
            WHERE id = ?
            LIMIT 1
            """,
            (client_id,)
        )
        existing_client = cursor.fetchone()

        if not existing_client:
            flash("Nie znaleziono klienta.", "error")
            return redirect(url_for("admin_clients"))

        cursor.execute(
            """
            UPDATE bookings
            SET client_id = NULL
            WHERE client_id = ?
            """,
            (client_id,)
        )

        cursor.execute(
            """
            DELETE FROM clients
            WHERE id = ?
            """,
            (client_id,)
        )

        conn.commit()
        flash("Karta klienta została usunięta.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_client:", e)
        flash("Nie udało się usunąć karty klienta.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_clients"))


from flask import jsonify

@app.route("/admin/clients/<int:client_id>/details")
@admin_required
def client_details(client_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT *
            FROM clients
            WHERE id = ?
            LIMIT 1
            """,
            (client_id,)
        )
        client = cursor.fetchone()

        if not client:
            return jsonify({"error": "Nie znaleziono klienta."}), 404

        preferred_employee_row = None
        if client["preferred_employee_id"]:
            cursor.execute(
                """
                SELECT id, full_name
                FROM employees
                WHERE id = ?
                LIMIT 1
                """,
                (client["preferred_employee_id"],)
            )
            preferred_employee_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                b.id,
                b.booking_date,
                b.booking_time,
                b.status,
                b.notes,
                b.archived,
                s.name AS service_name,
                e.full_name AS employee_name
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            WHERE b.client_id = ?
              AND COALESCE(b.archived, 0) = 0
              AND b.status IN ('new', 'confirmed')
            ORDER BY b.booking_date DESC, b.booking_time DESC, b.id DESC
            """,
            (client_id,)
        )
        active_bookings_rows = cursor.fetchall()

        cursor.execute(
            """
            SELECT
                b.id,
                b.booking_date,
                b.booking_time,
                b.status,
                b.notes,
                b.archived,
                s.name AS service_name,
                e.full_name AS employee_name
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            WHERE b.client_id = ?
            ORDER BY b.booking_date DESC, b.booking_time DESC, b.id DESC
            """,
            (client_id,)
        )
        history_rows = cursor.fetchall()

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM bookings
            WHERE client_id = ?
              AND COALESCE(archived, 0) = 0
              AND status IN ('new', 'confirmed')
            """,
            (client_id,)
        )
        active_count_row = cursor.fetchone()
        active_count = active_count_row["count"] if active_count_row else 0

        cursor.execute(
            """
            SELECT COUNT(*) AS count
            FROM bookings
            WHERE client_id = ?
              AND status = 'cancelled'
            """,
            (client_id,)
        )
        cancelled_count_row = cursor.fetchone()
        cancelled_count = cancelled_count_row["count"] if cancelled_count_row else 0

        cursor.execute(
            """
            SELECT
                e.full_name AS employee_name,
                COUNT(*) AS total
            FROM bookings b
            LEFT JOIN employees e ON e.id = b.employee_id
            WHERE b.client_id = ?
              AND b.employee_id IS NOT NULL
            GROUP BY b.employee_id, e.full_name
            ORDER BY total DESC, e.full_name ASC
            LIMIT 1
            """,
            (client_id,)
        )
        top_employee_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                s.name AS service_name,
                COUNT(*) AS total
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            WHERE b.client_id = ?
              AND b.service_id IS NOT NULL
            GROUP BY b.service_id, s.name
            ORDER BY total DESC, s.name ASC
            LIMIT 1
            """,
            (client_id,)
        )
        top_service_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                e.full_name AS employee_name
            FROM bookings b
            LEFT JOIN employees e ON e.id = b.employee_id
            WHERE b.client_id = ?
            ORDER BY b.booking_date DESC, b.booking_time DESC, b.id DESC
            LIMIT 1
            """,
            (client_id,)
        )
        last_employee_row = cursor.fetchone()

        response = {
            "client": {
                "id": client["id"],
                "full_name": client["full_name"],
                "phone": client["phone"],
                "email": client["email"],
                "client_status": client["client_status"],
                "is_regular": client["is_regular"],
                "notes": client["notes"],
                "created_at": client["created_at"],
                "updated_at": client["updated_at"],
                "preferred_employee_id": client["preferred_employee_id"],
            },
            "stats": {
                "active_bookings": active_count,
                "cancelled_bookings": cancelled_count,
            },
            "preferences": {
                "preferred_employee_id": client["preferred_employee_id"],
                "preferred_employee": preferred_employee_row["full_name"]
                if preferred_employee_row and preferred_employee_row["full_name"]
                else None,
                "top_employee": top_employee_row["employee_name"]
                if top_employee_row and top_employee_row["employee_name"]
                else None,
                "top_service": top_service_row["service_name"]
                if top_service_row and top_service_row["service_name"]
                else None,
                "last_employee": last_employee_row["employee_name"]
                if last_employee_row and last_employee_row["employee_name"]
                else None,
            },
            "consents": {
                "privacy_consent": client["privacy_consent"],
                "marketing_consent": client["marketing_consent"],
                "privacy_consent_at": client["privacy_consent_at"],
                "marketing_consent_at": client["marketing_consent_at"],
                "consent_source": client["consent_source"],
                "privacy_notice_confirmed": client["privacy_notice_confirmed"],
                "privacy_notice_confirmed_at": client["privacy_notice_confirmed_at"],
                "privacy_notice_source": client["privacy_notice_source"],
            },
            "active_bookings": [
                {
                    "id": row["id"],
                    "booking_date": row["booking_date"],
                    "booking_time": row["booking_time"],
                    "status": row["status"],
                    "notes": row["notes"],
                    "archived": row["archived"],
                    "service_name": row["service_name"],
                    "employee_name": row["employee_name"],
                }
                for row in active_bookings_rows
            ],
            "history": [
                {
                    "id": row["id"],
                    "booking_date": row["booking_date"],
                    "booking_time": row["booking_time"],
                    "status": row["status"],
                    "notes": row["notes"],
                    "archived": row["archived"],
                    "service_name": row["service_name"],
                    "employee_name": row["employee_name"],
                }
                for row in history_rows
            ],
        }

        return jsonify(response)

    except Exception as e:
        print("Błąd client_details:", e)
        return jsonify({"error": "Nie udało się pobrać szczegółów klienta."}), 500

    finally:
        conn.close()


@app.route("/admin/settings/booking-media/update", methods=["POST"])
@admin_required
def update_booking_media_settings():
    side_panels_enabled = 1 if request.form.get("side_panels_enabled") == "1" else 0
    side_panels_autoplay = 1 if request.form.get("side_panels_autoplay") == "1" else 0
    side_panels_interval = request.form.get("side_panels_interval", type=int)

    if side_panels_interval is None:
        side_panels_interval = 6

    side_panels_interval = max(3, min(20, side_panels_interval))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE business_settings
            SET
                side_panels_enabled = ?,
                side_panels_autoplay = ?,
                side_panels_interval = ?
            WHERE id = 1
        """, (
            side_panels_enabled,
            side_panels_autoplay,
            side_panels_interval
        ))

        conn.commit()
        flash("Ustawienia paneli bocznych zostały zapisane.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd update_booking_media_settings:", e)
        flash("Nie udało się zapisać ustawień paneli bocznych.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/add", methods=["POST"])
@admin_required
def add_booking_side_image():
    side = (request.form.get("side") or "").strip().lower()
    image = request.files.get("image")

    if side not in ("left", "right"):
        flash("Wybierz poprawną stronę zdjęcia.", "error")
        return redirect(url_for("admin_settings"))

    if not image or not image.filename:
        flash("Wybierz plik zdjęcia.", "error")
        return redirect(url_for("admin_settings"))

    original_filename = secure_filename(image.filename)
    _, extension = os.path.splitext(original_filename)
    extension = extension.lower()

    allowed_extensions = {".png", ".jpg", ".jpeg", ".webp"}

    if extension not in allowed_extensions:
        flash("Dozwolone formaty zdjęcia to: PNG, JPG, JPEG, WEBP.", "error")
        return redirect(url_for("admin_settings"))

    os.makedirs(UPLOAD_BOOKING_SIDE_IMAGES_DIR, exist_ok=True)

    filename = f"booking_side_{side}_{uuid.uuid4().hex}{extension}"
    save_path = os.path.join(UPLOAD_BOOKING_SIDE_IMAGES_DIR, filename)

    try:
        image.save(save_path)
        relative_path = os.path.join("uploads", "booking_side_images", filename).replace("\\", "/")

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order
            FROM booking_side_images
            WHERE side = ?
        """, (side,))
        next_order_row = cursor.fetchone()
        next_order = next_order_row["next_order"] if next_order_row and next_order_row["next_order"] else 1

        cursor.execute("""
            INSERT INTO booking_side_images (
                side,
                image_path,
                sort_order,
                is_active
            )
            VALUES (?, ?, ?, 1)
        """, (
            side,
            relative_path,
            next_order
        ))

        conn.commit()
        flash("Zdjęcie boczne zostało dodane.", "success")

    except Exception as e:
        print("Błąd add_booking_side_image:", e)
        flash("Nie udało się dodać zdjęcia bocznego.", "error")

    finally:
        try:
            conn.close()
        except Exception:
            pass

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/<int:image_id>/delete", methods=["POST"])
@admin_required
def delete_booking_side_image(image_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT image_path
            FROM booking_side_images
            WHERE id = ?
            LIMIT 1
        """, (image_id,))
        row = cursor.fetchone()

        if not row:
            flash("Nie znaleziono zdjęcia.", "error")
            return redirect(url_for("admin_settings"))

        image_path = row["image_path"]
        absolute_path = os.path.join(app.static_folder, image_path)

        cursor.execute("DELETE FROM booking_side_images WHERE id = ?", (image_id,))
        conn.commit()

        if image_path and os.path.exists(absolute_path):
            try:
                os.remove(absolute_path)
            except OSError:
                pass

        flash("Zdjęcie zostało usunięte.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_booking_side_image:", e)
        flash("Nie udało się usunąć zdjęcia.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/<int:image_id>/move-up", methods=["POST"])
@admin_required
def move_booking_side_image_up(image_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, side, sort_order
            FROM booking_side_images
            WHERE id = ?
            LIMIT 1
        """, (image_id,))
        current = cursor.fetchone()

        if not current:
            flash("Nie znaleziono zdjęcia.", "error")
            return redirect(url_for("admin_settings"))

        cursor.execute("""
            SELECT id, sort_order
            FROM booking_side_images
            WHERE side = ?
              AND sort_order < ?
            ORDER BY sort_order DESC, id DESC
            LIMIT 1
        """, (
            current["side"],
            current["sort_order"]
        ))
        previous_row = cursor.fetchone()

        if previous_row:
            cursor.execute(
                "UPDATE booking_side_images SET sort_order = ? WHERE id = ?",
                (previous_row["sort_order"], current["id"])
            )
            cursor.execute(
                "UPDATE booking_side_images SET sort_order = ? WHERE id = ?",
                (current["sort_order"], previous_row["id"])
            )
            conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd move_booking_side_image_up:", e)
        flash("Nie udało się zmienić kolejności zdjęcia.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/<int:image_id>/move-down", methods=["POST"])
@admin_required
def move_booking_side_image_down(image_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, side, sort_order
            FROM booking_side_images
            WHERE id = ?
            LIMIT 1
        """, (image_id,))
        current = cursor.fetchone()

        if not current:
            flash("Nie znaleziono zdjęcia.", "error")
            return redirect(url_for("admin_settings"))

        cursor.execute("""
            SELECT id, sort_order
            FROM booking_side_images
            WHERE side = ?
              AND sort_order > ?
            ORDER BY sort_order ASC, id ASC
            LIMIT 1
        """, (
            current["side"],
            current["sort_order"]
        ))
        next_row = cursor.fetchone()

        if next_row:
            cursor.execute(
                "UPDATE booking_side_images SET sort_order = ? WHERE id = ?",
                (next_row["sort_order"], current["id"])
            )
            cursor.execute(
                "UPDATE booking_side_images SET sort_order = ? WHERE id = ?",
                (current["sort_order"], next_row["id"])
            )
            conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd move_booking_side_image_down:", e)
        flash("Nie udało się zmienić kolejności zdjęcia.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))



        
# =========================================================
# RUN
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)