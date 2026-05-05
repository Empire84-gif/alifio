import os
import re
import json
import uuid
import unicodedata
import mimetypes
import requests
import base64
import binascii
import secrets

from datetime import datetime, timedelta
from functools import wraps
from textwrap import dedent
from urllib.parse import urlparse

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

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
    get_user_by_email,
    get_user_by_id,
    verify_password,
    update_user_password,
    update_user_last_login,
    create_client_admin,
    create_staff_user,
)
from services.token_service import (
    create_password_reset_token,
    get_valid_reset_token,
    mark_token_as_used,
)
from services.account_activation_service import (
    create_account_activation_invite,
    get_valid_account_activation_invite,
    mark_account_activation_invite_as_used,
    build_activation_link,
)
from services.email_notifications import (
    send_email_smtp,
    send_email_message,
    send_booking_verification_email,
    send_waitlist_verification_email,
    send_booking_internal_notifications,
    send_waitlist_internal_notifications,
    send_booking_cancellation_notifications,
    send_booking_cancellation_internal_notifications,
    send_booking_cancellation_confirmation_email,
    assign_client_verification_token,
    get_or_assign_client_action_token,
    attach_client_action_links,
)

from services.booking_cancel_tokens import (
    create_booking_cancel_token,
    get_booking_cancel_token_record,
    is_booking_cancel_token_valid,
    mark_booking_cancel_token_used,
)


TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "").strip()

def is_turnstile_enabled():
    return os.getenv("TURNSTILE_ENABLED", "0").strip().lower() in ("1", "true", "yes", "on")

TURNSTILE_ENABLED = is_turnstile_enabled()

# =========================================================
# STAŁE / UPLOAD / R2
# =========================================================

UPLOAD_EMPLOYEES_DIR = os.path.join("static", "images")
UPLOAD_BOOKING_SIDE_IMAGES_DIR = os.path.join("static", "uploads", "booking_side_images")

R2_BUCKET_NAME = os.getenv("R2_BUCKET_NAME", "").strip()
R2_ENDPOINT_URL = os.getenv("R2_ENDPOINT_URL", "").strip()
R2_ACCESS_KEY_ID = os.getenv("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.getenv("R2_SECRET_ACCESS_KEY", "").strip()
R2_REGION = os.getenv("R2_REGION", "auto").strip()
R2_PUBLIC_BASE_URL = os.getenv("R2_PUBLIC_BASE_URL", "").strip()
USE_R2_STORAGE = os.getenv("USE_R2_STORAGE", "0") == "1"

# =========================================================
# APP
# =========================================================

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.permanent_session_lifetime = PERMANENT_SESSION_LIFETIME

app.config["MAIL_FROM_EMAIL"] = os.getenv("MAIL_FROM_EMAIL", "admin@handkeholding.com")
app.config["MAIL_SMTP_HOST"] = os.getenv("MAIL_SMTP_HOST", "smtp.zone.eu")
app.config["MAIL_SMTP_PORT"] = int(os.getenv("MAIL_SMTP_PORT", "465"))
app.config["MAIL_SMTP_USERNAME"] = os.getenv("MAIL_SMTP_USERNAME", "admin@handkeholding.com")
app.config["MAIL_SMTP_PASSWORD"] = os.getenv("MAIL_SMTP_PASSWORD", "")
app.config["MAIL_SMTP_USE_TLS"] = os.getenv("MAIL_SMTP_USE_TLS", "false").lower() == "true"
app.config["MAIL_SMTP_USE_SSL"] = os.getenv("MAIL_SMTP_USE_SSL", "true").lower() == "true"
app.config["INTERNAL_TASK_TOKEN"] = os.getenv("INTERNAL_TASK_TOKEN", "").strip()

# =========================================================
# STORAGE HELPERS / R2
# =========================================================

def r2_is_configured() -> bool:
    return all([
        R2_BUCKET_NAME,
        R2_ENDPOINT_URL,
        R2_ACCESS_KEY_ID,
        R2_SECRET_ACCESS_KEY,
    ])


def get_r2_client():
    if not r2_is_configured():
        raise RuntimeError("Cloudflare R2 nie jest poprawnie skonfigurowany.")

    return boto3.client(
        "s3",
        endpoint_url=R2_ENDPOINT_URL,
        aws_access_key_id=R2_ACCESS_KEY_ID,
        aws_secret_access_key=R2_SECRET_ACCESS_KEY,
        region_name=R2_REGION,
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "path"},
        ),
    )


def upload_fileobj_to_r2(fileobj, object_key: str, content_type: str | None = None) -> str:
    client = get_r2_client()

    extra_args = {}
    if content_type:
        extra_args["ContentType"] = content_type

    fileobj.seek(0)

    client.upload_fileobj(
        Fileobj=fileobj,
        Bucket=R2_BUCKET_NAME,
        Key=object_key,
        ExtraArgs=extra_args,
    )

    return object_key


def upload_bytes_to_r2(file_bytes: bytes, object_key: str, content_type: str | None = None) -> str:
    client = get_r2_client()

    extra_args = {}
    if content_type:
        extra_args["ContentType"] = content_type

    client.put_object(
        Bucket=R2_BUCKET_NAME,
        Key=object_key,
        Body=file_bytes,
        **extra_args,
    )

    return object_key


def extract_r2_object_key(file_path_or_url: str | None) -> str | None:
    value = (file_path_or_url or "").strip()
    if not value:
        return None

    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        path = parsed.path.lstrip("/")

        bucket_prefix = f"{R2_BUCKET_NAME}/"
        if path.startswith(bucket_prefix):
            return path[len(bucket_prefix):]

        return path

    return value


def delete_r2_file(file_path_or_url: str | None) -> None:
    object_key = extract_r2_object_key(file_path_or_url)
    if not object_key:
        return

    try:
        client = get_r2_client()
        client.delete_object(Bucket=R2_BUCKET_NAME, Key=object_key)
    except Exception as e:
        print("Błąd delete_r2_file:", e)


def media_url(file_path_or_url: str | None) -> str:
    value = (file_path_or_url or "").strip()
    if not value:
        return ""

    if value.startswith("http://") or value.startswith("https://"):
        return value

    if value.startswith("images/") or value.startswith("uploads/"):
        return url_for("static", filename=value)

    if USE_R2_STORAGE and r2_is_configured():
        if R2_PUBLIC_BASE_URL:
            return f"{R2_PUBLIC_BASE_URL.rstrip('/')}/{value.lstrip('/')}"
        return f"{R2_ENDPOINT_URL.rstrip('/')}/{R2_BUCKET_NAME}/{value.lstrip('/')}"

    return value


app.jinja_env.globals["media_url"] = media_url

# =========================================================
# BASIC HELPERS
# =========================================================

def get_settings(business_id=None):
    if business_id is None:
        business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM business_settings WHERE business_id = ? LIMIT 1",
        (business_id,)
    )
    settings = cursor.fetchone()

    if not settings:
        cursor.execute("SELECT * FROM business_settings WHERE id = 1 LIMIT 1")
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


def login_admin(user, remember_me=False):
    session.clear()

    session["admin_logged_in"] = True
    session["admin_id"] = user["id"]
    session["admin_email"] = user["email"]
    session["admin_full_name"] = user["full_name"]
    session["admin_role"] = user["role"]
    session["business_id"] = user["business_id"]

    session["can_manage_bookings"] = int(user["can_manage_bookings"] or 0)
    session["can_view_clients"] = int(user["can_view_clients"] or 0)
    session["can_edit_clients"] = int(user["can_edit_clients"] or 0)
    session["can_view_reports"] = int(user["can_view_reports"] or 0)
    session["can_manage_services"] = int(user["can_manage_services"] or 0)
    session["can_manage_settings"] = int(user["can_manage_settings"] or 0)
    session["can_manage_staff"] = int(user["can_manage_staff"] or 0)
    session["can_manage_security"] = int(user["can_manage_security"] or 0)

    session.permanent = bool(remember_me)


def logout_admin():
    session.clear()


def get_current_admin_user():
    user_id = session.get("admin_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user_id = session.get("admin_id")
        if not session.get("admin_logged_in") or not user_id:
            flash("Zaloguj się, aby uzyskać dostęp do panelu administratora.", "error")
            return redirect(url_for("admin_login"))

        current_user = get_user_by_id(user_id)
        if not current_user or int(current_user["is_active"]) != 1:
            session.clear()
            flash("Sesja wygasła. Zaloguj się ponownie.", "error")
            return redirect(url_for("admin_login"))

        return view_func(*args, **kwargs)

    return wrapper


def current_user_is_staff():
    user = get_current_admin_user()
    return bool(user and user["role"] == "staff")


def current_user_is_client_admin():
    user = get_current_admin_user()
    return bool(user and user["role"] in ("client_admin", "super_admin"))


def current_staff_employee_id():
    user = get_current_admin_user()
    if not user or user["role"] != "staff":
        return None
    return user["employee_id"]


def current_user_can_view_clients():
    user = get_current_admin_user()
    if not user:
        return False

    if user["role"] in ("client_admin", "super_admin"):
        return True

    return int(user["can_view_clients"] or 0) == 1


def current_user_can_edit_clients():
    user = get_current_admin_user()
    if not user:
        return False

    if user["role"] in ("client_admin", "super_admin"):
        return True

    return int(user["can_edit_clients"] or 0) == 1


def current_user_can_view_reports():
    user = get_current_admin_user()
    if not user:
        return False

    if user["role"] in ("client_admin", "super_admin"):
        return True

    return int(user["can_view_reports"] or 0) == 1


def client_admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_admin_user()

        if not user:
            flash("Zaloguj się ponownie.", "error")
            return redirect(url_for("admin_login"))

        if user["role"] not in ("client_admin", "super_admin"):
            flash("To konto nie ma dostępu do tej sekcji.", "error")
            return redirect(url_for("admin_dashboard"))

        return view_func(*args, **kwargs)

    return wrapper


def permission_required(permission_name):
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            user = get_current_admin_user()

            if not user:
                flash("Zaloguj się ponownie.", "error")
                return redirect(url_for("admin_login"))

            if user["role"] in ("client_admin", "super_admin"):
                return view_func(*args, **kwargs)

            if int(user[permission_name] or 0) != 1:
                flash("To konto nie ma dostępu do tej operacji.", "error")
                return redirect(url_for("admin_dashboard"))

            return view_func(*args, **kwargs)

        return wrapper

    return decorator


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
            (service_id, employee_id, booking_date, booking_date, booking_time, booking_time),
        )
        return cursor.fetchall()
    finally:
        conn.close()


def mark_first_waitlist_match_for_slot(service_id, employee_id, booking_date, booking_time):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
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
            """,
            (
                service_id,
                employee_id,
                booking_date,
                booking_date,
                booking_time,
                booking_time,
            ),
        )

        match_row = cursor.fetchone()

        if not match_row:
            return

        cursor.execute(
            """
            UPDATE waitlist_entries
            SET
                status = 'matched',
                matched_booking_date = ?,
                matched_booking_time = ?
            WHERE id = ?
            """,
            (
                booking_date,
                booking_time,
                match_row["id"],
            ),
        )

        conn.commit()

    finally:
        conn.close()


def clear_waitlist_match(waitlist_entry_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE waitlist_entries
            SET
                status = 'waiting',
                matched_booking_date = NULL,
                matched_booking_time = NULL
            WHERE id = ?
            """,
            (waitlist_entry_id,),
        )
        conn.commit()
    finally:
        conn.close()


def slugify_business_name(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9\s-]", "", value)
    value = re.sub(r"[\s_-]+", "-", value)
    value = re.sub(r"^-+|-+$", "", value)
    return value or "business"


def ensure_unique_business_slug(base_slug: str) -> str:
    conn = get_connection()
    cursor = conn.cursor()

    try:
        slug = base_slug
        counter = 2

        while True:
            cursor.execute(
                """
                SELECT id
                FROM businesses
                WHERE slug = ?
                LIMIT 1
                """,
                (slug,),
            )
            existing = cursor.fetchone()

            if not existing:
                return slug

            slug = f"{base_slug}-{counter}"
            counter += 1
    finally:
        conn.close()


def format_booking_date_pl(date_value):
    if not date_value:
        return "—"

    try:
        if isinstance(date_value, str):
            return datetime.strptime(date_value, "%Y-%m-%d").strftime("%d.%m.%Y")
        return str(date_value)
    except Exception:
        return str(date_value)


def safe_booking_value(value, fallback="—"):
    return value if value not in (None, "", []) else fallback


def get_booking_notification_context(booking_row):
    return {
        "booking_id": booking_row.get("id"),

        # klient
        "client_id": booking_row.get("client_id"),
        "client_name": safe_booking_value(booking_row.get("client_name"), "Kliencie"),
        "client_email": booking_row.get("client_email"),
        "client_email_verified": int(booking_row.get("client_email_verified") or 0),
        "client_phone": safe_booking_value(booking_row.get("client_phone")),

        # usługa / pracownik
        "service_name": safe_booking_value(booking_row.get("service_name")),
        "employee_name": safe_booking_value(booking_row.get("employee_name")),
        "employee_email": booking_row.get("employee_email"),

        # termin
        "booking_date": booking_row.get("booking_date"),
        "booking_date_pl": format_booking_date_pl(booking_row.get("booking_date")),
        "booking_time": safe_booking_value(booking_row.get("booking_time")),

        # firma (ważne dla maili)
        "company_name": safe_booking_value(
            booking_row.get("company_name") or booking_row.get("business_name"),
            "Salon",
        ),
        "company_address": booking_row.get("company_address") or "",
        "contact_phone": booking_row.get("contact_phone") or "",
        "contact_email": booking_row.get("salon_email") or "",
        "website_url": booking_row.get("website_url") or "",
        "privacy_policy_url": booking_row.get("privacy_policy_url") or "",

        # legacy / kompatybilność (jeśli gdzieś używasz)
        "salon_email": booking_row.get("salon_email"),
    }


def send_booking_status_changed_emails(notification_ctx, new_status):
    normalized_status = (new_status or "").strip().lower()

    company_name = safe_booking_value(
        notification_ctx.get("company_name"),
        "Salon",
    )

    client_name = safe_booking_value(
        notification_ctx.get("client_name"),
        "Kliencie",
    )

    client_email = (notification_ctx.get("client_email") or "").strip()
    client_email_verified = int(notification_ctx.get("client_email_verified") or 0)
    employee_email = (notification_ctx.get("employee_email") or "").strip()
    salon_email = (notification_ctx.get("salon_email") or "").strip()

    # Bezpieczne linki dla klienta do stopki.
    # Jeśli funkcje linków nie są dostępne albo coś się wysypie,
    # mail statusowy i tak ma zostać wysłany.
    client_links = {
        "unsubscribe_booking_emails_url": "",
        "withdraw_marketing_consent_url": "",
    }

    client_id = notification_ctx.get("client_id")

    try:
        if (
            client_id
            and "get_or_assign_client_action_token" in globals()
            and "attach_client_action_links" in globals()
        ):
            client_action_token = get_or_assign_client_action_token(client_id)
            client_links = attach_client_action_links({}, client_action_token)
    except Exception as exc:
        print(f"[MAIL][STATUS][LINKS] Linki stopki pominięte: {exc}")

    common_data = {
        "company_name": company_name,
        "company_address": notification_ctx.get("company_address") or "",
        "contact_phone": notification_ctx.get("contact_phone") or "",
        "contact_email": notification_ctx.get("contact_email") or "",
        "website_url": notification_ctx.get("website_url") or "",

        "client_name": client_name,
        "client_email": safe_booking_value(notification_ctx.get("client_email")),
        "client_phone": safe_booking_value(notification_ctx.get("client_phone")),
        "service_name": safe_booking_value(notification_ctx.get("service_name")),
        "employee_name": safe_booking_value(notification_ctx.get("employee_name")),
        "booking_date_pl": safe_booking_value(notification_ctx.get("booking_date_pl")),
        "booking_time": safe_booking_value(notification_ctx.get("booking_time")),
        "booking_id": safe_booking_value(notification_ctx.get("booking_id")),
    }

    client_data = {
        **common_data,
        "privacy_policy_url": notification_ctx.get("privacy_policy_url") or "",
        "unsubscribe_booking_emails_url": client_links.get("unsubscribe_booking_emails_url", ""),
        "withdraw_marketing_consent_url": client_links.get("withdraw_marketing_consent_url", ""),
    }

    internal_data = {
        **common_data,
        "privacy_policy_url": "",
        "unsubscribe_booking_emails_url": "",
        "withdraw_marketing_consent_url": "",
    }

    if normalized_status == "cancelled":
        client_subject = "Anulowanie rezerwacji"

        client_html = render_template(
            "emails/booking_status_client.html",
            email_title=client_subject,
            email_heading="Rezerwacja została anulowana",
            intro_text="Informujemy, że Twoja rezerwacja została anulowana.",
            extra_note="W celu wybrania innego terminu dokonaj nowej rezerwacji przez formularz online dostępny na stronie.",
            **client_data,
        )

        client_text = dedent(f"""
            Dzień dobry {client_name},

            informujemy, że Twoja rezerwacja została anulowana.

            Szczegóły wizyty:
            • Usługa: {common_data['service_name']}
            • Specjalista / Specjalistka: {common_data['employee_name']}
            • Data wizyty: {common_data['booking_date_pl']}
            • Godzina wizyty: {common_data['booking_time']}

            W celu ustalenia nowego terminu skorzystaj z formularza online dostępnego na stronie — system pokaże aktualnie dostępne terminy.

            Pozdrawiamy,
            {company_name}
        """).strip()

        internal_subject = "Anulowano rezerwację klienta"

        internal_html = render_template(
            "emails/booking_status_internal.html",
            email_title=internal_subject,
            email_heading="Rezerwacja została anulowana",
            intro_text="W systemie odnotowano anulowanie rezerwacji klienta. Poniżej znajdują się szczegóły wizyty.",
            **internal_data,
        )

        internal_text = dedent(f"""
            W systemie odnotowano anulowanie rezerwacji klienta.

            Szczegóły rezerwacji:
            • Klient: {common_data['client_name']}
            • Telefon: {common_data['client_phone']}
            • E-mail: {common_data['client_email']}
            • Usługa: {common_data['service_name']}
            • Specjalista / Specjalistka: {common_data['employee_name']}
            • Data wizyty: {common_data['booking_date_pl']}
            • Godzina wizyty: {common_data['booking_time']}
            • ID rezerwacji: {common_data['booking_id']}
        """).strip()

    elif normalized_status == "confirmed":
        client_subject = "Potwierdzenie rezerwacji"

        client_html = render_template(
            "emails/booking_status_client.html",
            email_title=client_subject,
            email_heading="Rezerwacja została potwierdzona",
            intro_text="Z przyjemnością potwierdzamy Twoją rezerwację.",
            extra_note="Dziękujemy za zaufanie i do zobaczenia.",
            **client_data,
        )

        client_text = dedent(f"""
            Dzień dobry {client_name},

            z przyjemnością potwierdzamy Twoją rezerwację.

            Szczegóły wizyty:
            • Usługa: {common_data['service_name']}
            • Specjalista / Specjalistka: {common_data['employee_name']}
            • Data wizyty: {common_data['booking_date_pl']}
            • Godzina wizyty: {common_data['booking_time']}

            Dziękujemy za zaufanie i do zobaczenia.

            Pozdrawiamy,
            {company_name}
        """).strip()

        internal_subject = "Potwierdzono rezerwację klienta"

        internal_html = render_template(
            "emails/booking_status_internal.html",
            email_title=internal_subject,
            email_heading="Rezerwacja została potwierdzona",
            intro_text="W systemie potwierdzono rezerwację klienta. Poniżej znajdują się szczegóły wizyty.",
            **internal_data,
        )

        internal_text = dedent(f"""
            W systemie potwierdzono rezerwację klienta.

            Szczegóły rezerwacji:
            • Klient: {common_data['client_name']}
            • Telefon: {common_data['client_phone']}
            • E-mail: {common_data['client_email']}
            • Usługa: {common_data['service_name']}
            • Specjalista / Specjalistka: {common_data['employee_name']}
            • Data wizyty: {common_data['booking_date_pl']}
            • Godzina wizyty: {common_data['booking_time']}
            • ID rezerwacji: {common_data['booking_id']}
        """).strip()

    else:
        return

    if client_email and client_email_verified == 1:
        try:
            send_email_smtp(
                to_email=client_email,
                subject=client_subject,
                html_body=client_html,
                text_body=client_text,
            )
        except Exception as exc:
            print(f"[MAIL][STATUS][CLIENT] Błąd wysyłki: {exc}")

    if employee_email:
        try:
            send_email_smtp(
                to_email=employee_email,
                subject=internal_subject,
                html_body=internal_html,
                text_body=internal_text,
            )
        except Exception as exc:
            print(f"[MAIL][STATUS][EMPLOYEE] Błąd wysyłki: {exc}")

    if salon_email:
        try:
            send_email_smtp(
                to_email=salon_email,
                subject=internal_subject,
                html_body=internal_html,
                text_body=internal_text,
            )
        except Exception as exc:
            print(f"[MAIL][STATUS][SALON] Błąd wysyłki: {exc}")


def send_waitlist_promoted_emails(notification_ctx):
    company_name = safe_booking_value(notification_ctx.get("company_name"), "Salon")
    client_name = safe_booking_value(notification_ctx.get("client_name"), "Kliencie")

    client_subject = "Znaleziono termin — rezerwacja została utworzona"
    client_body = dedent(f"""
        Dzień dobry {client_name},

        informujemy, że pojawił się dostępny termin, a Twoje zgłoszenie z listy oczekujących zostało przeniesione do aktywnej rezerwacji.

        Szczegóły wizyty:
        • Usługa: {safe_booking_value(notification_ctx.get('service_name'))}
        • Specjalista / Specjalistka: {safe_booking_value(notification_ctx.get('employee_name'))}
        • Data wizyty: {safe_booking_value(notification_ctx.get('booking_date_pl'))}
        • Godzina wizyty: {safe_booking_value(notification_ctx.get('booking_time'))}

        Dziękujemy za zaufanie.

        Pozdrawiamy,
        {company_name}
    """).strip()

    internal_subject = "Przeniesiono klienta z listy oczekujących do rezerwacji"
    internal_body = dedent(f"""
        Klient z listy oczekujących został przeniesiony do aktywnej rezerwacji.

        Szczegóły rezerwacji:
        • Klient: {safe_booking_value(notification_ctx.get('client_name'))}
        • Telefon: {safe_booking_value(notification_ctx.get('client_phone'))}
        • E-mail: {safe_booking_value(notification_ctx.get('client_email'))}
        • Usługa: {safe_booking_value(notification_ctx.get('service_name'))}
        • Specjalista / Specjalistka: {safe_booking_value(notification_ctx.get('employee_name'))}
        • Data wizyty: {safe_booking_value(notification_ctx.get('booking_date_pl'))}
        • Godzina wizyty: {safe_booking_value(notification_ctx.get('booking_time'))}
        • ID rezerwacji: {safe_booking_value(notification_ctx.get('booking_id'))}
    """).strip()

    client_email = notification_ctx.get("client_email")
    employee_email = notification_ctx.get("employee_email")
    salon_email = notification_ctx.get("salon_email")

    if client_email:
        try:
            send_email_smtp(client_email, client_subject, client_body)
        except Exception as exc:
            print(f"[MAIL][WAITLIST->BOOKING][CLIENT] Błąd wysyłki: {exc}")

    if employee_email:
        try:
            send_email_smtp(employee_email, internal_subject, internal_body)
        except Exception as exc:
            print(f"[MAIL][WAITLIST->BOOKING][EMPLOYEE] Błąd wysyłki: {exc}")

    if salon_email:
        try:
            send_email_smtp(salon_email, internal_subject, internal_body)
        except Exception as exc:
            print(f"[MAIL][WAITLIST->BOOKING][SALON] Błąd wysyłki: {exc}")


def format_booking_date_long_pl(date_value):
    if not date_value:
        return "—"

    try:
        dt = datetime.strptime(date_value, "%Y-%m-%d")
        return dt.strftime("%d.%m.%Y")
    except Exception:
        return str(date_value)


def send_booking_reminder_emails(notification_ctx):
    company_name = safe_booking_value(notification_ctx.get("company_name"), "Salon")
    client_name = safe_booking_value(notification_ctx.get("client_name"), "Kliencie")

    client_email = notification_ctx.get("client_email")
    employee_email = notification_ctx.get("employee_email")
    salon_email = notification_ctx.get("salon_email")

    client_subject = "Przypomnienie o jutrzejszej wizycie"
    client_body = dedent(f"""
        Dzień dobry {client_name},

        przypominamy o jutrzejszej wizycie.

        Szczegóły rezerwacji:
        • Usługa: {safe_booking_value(notification_ctx.get('service_name'))}
        • Specjalista / Specjalistka: {safe_booking_value(notification_ctx.get('employee_name'))}
        • Data wizyty: {safe_booking_value(notification_ctx.get('booking_date_pl'))}
        • Godzina wizyty: {safe_booking_value(notification_ctx.get('booking_time'))}

        W razie potrzeby zmiany terminu lub dodatkowych pytań prosimy o kontakt z salonem.

        Pozdrawiamy,
        {company_name}
    """).strip()

    internal_subject = "Przypomnienie o jutrzejszej rezerwacji"
    internal_body = dedent(f"""
        To automatyczne przypomnienie o jutrzejszej rezerwacji.

        Szczegóły rezerwacji:
        • Klient: {safe_booking_value(notification_ctx.get('client_name'))}
        • Telefon: {safe_booking_value(notification_ctx.get('client_phone'))}
        • E-mail: {safe_booking_value(notification_ctx.get('client_email'))}
        • Usługa: {safe_booking_value(notification_ctx.get('service_name'))}
        • Specjalista / Specjalistka: {safe_booking_value(notification_ctx.get('employee_name'))}
        • Data wizyty: {safe_booking_value(notification_ctx.get('booking_date_pl'))}
        • Godzina wizyty: {safe_booking_value(notification_ctx.get('booking_time'))}
        • ID rezerwacji: {safe_booking_value(notification_ctx.get('booking_id'))}
    """).strip()

    if client_email:
        try:
            send_email_smtp(client_email, client_subject, client_body)
        except Exception as exc:
            print(f"[MAIL][REMINDER][CLIENT] Błąd wysyłki: {exc}")

    if employee_email:
        try:
            send_email_smtp(employee_email, internal_subject, internal_body)
        except Exception as exc:
            print(f"[MAIL][REMINDER][EMPLOYEE] Błąd wysyłki: {exc}")

    if salon_email:
        try:
            send_email_smtp(salon_email, internal_subject, internal_body)
        except Exception as exc:
            print(f"[MAIL][REMINDER][SALON] Błąd wysyłki: {exc}")


def send_day_before_booking_reminders():
    tomorrow = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
    sent_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    sent_count = 0
    failed_count = 0

    try:
        cursor.execute(
            """
            SELECT
                b.id
            FROM bookings b
            WHERE b.booking_date = ?
              AND COALESCE(b.archived, 0) = 0
              AND COALESCE(b.reminder_sent_at, '') = ''
              AND LOWER(COALESCE(b.status, '')) IN ('new', 'confirmed')
            ORDER BY b.booking_time ASC, b.id ASC
            """,
            (tomorrow,),
        )

        booking_rows = cursor.fetchall()

        for row in booking_rows:
            booking_id = row["id"]

            try:
                booking_data = fetch_booking_notification_data(booking_id)
                if not booking_data:
                    failed_count += 1
                    continue

                notification_ctx = get_booking_notification_context(booking_data)
                send_booking_reminder_emails(notification_ctx)

                cursor.execute(
                    """
                    UPDATE bookings
                    SET reminder_sent_at = ?
                    WHERE id = ?
                    """,
                    (sent_at, booking_id),
                )

                sent_count += 1

            except Exception as exc:
                failed_count += 1
                print(f"[MAIL][REMINDER] Błąd dla booking_id={booking_id}: {exc}")

        conn.commit()
        return {
            "success": True,
            "sent_count": sent_count,
            "failed_count": failed_count,
            "target_date": tomorrow,
        }

    except Exception as exc:
        conn.rollback()
        print(f"[MAIL][REMINDER] Błąd główny: {exc}")
        return {
            "success": False,
            "sent_count": sent_count,
            "failed_count": failed_count,
            "target_date": tomorrow,
            "error": str(exc),
        }

    finally:
        conn.close()

def calculate_client_status(completed_visits, last_completed_visit_at, next_booking_at=None):
    from datetime import datetime, timedelta

    total = int(completed_visits or 0)
    now = datetime.now()

    last_visit = None
    next_booking = None

    def parse_datetime(value):
        if not value:
            return None

        value = str(value).strip()

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        return None

    last_visit = parse_datetime(last_completed_visit_at)
    next_booking = parse_datetime(next_booking_at)

    has_future_booking = bool(next_booking and next_booking >= now)

    # 0 odbytych wizyt
    if total == 0:
        return "new"

    # klient ma przyszłą wizytę, więc nie może być inactive
    if has_future_booking:
        if total >= 6:
            return "vip"
        if total >= 3:
            return "regular"
        return "active"

    # brak daty ostatniej wizyty, ale coś w historii jest
    if not last_visit:
        return "active"

    days_since_last = (now - last_visit).days

    if days_since_last > 90:
        return "inactive"

    if days_since_last > 45:
        return "at_risk"

    if total >= 6:
        return "vip"

    if total >= 3:
        return "regular"

    return "active"

def ensure_clients_blacklist_columns():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        ensure_column(cursor, "clients", "blacklisted", "blacklisted INTEGER DEFAULT 0")
        ensure_column(cursor, "clients", "blacklist_reason", "blacklist_reason TEXT")
        ensure_column(cursor, "clients", "blacklisted_at", "blacklisted_at TEXT")
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


def normalize_text_date_to_db(value: str | None) -> str:
    value = (value or "").strip()
    if not value:
        return ""

    for fmt in ("%d.%m.%Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue

    return ""


def normalize_text_time_value(value: str | None) -> str:
    value = (value or "").strip()
    if not value:
        return ""

    try:
        return datetime.strptime(value, "%H:%M").strftime("%H:%M")
    except ValueError:
        return ""


def delete_static_file(relative_path: str | None):
    if not relative_path:
        return

    file_path = os.path.join(app.static_folder, relative_path)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except OSError:
            pass


def send_pending_status_emails_after_client_verification(client_id: int):
    if not client_id:
        return

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                b.id,
                b.business_id,
                b.client_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.status,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.contact_email AS salon_email,
                biz.name AS business_name,
                COALESCE(c.email_verified, 0) AS client_email_verified
            FROM bookings b
            LEFT JOIN services s
                ON s.id = b.service_id
            LEFT JOIN employees e
                ON e.id = b.employee_id
            LEFT JOIN business_settings bs
                ON bs.business_id = b.business_id
            LEFT JOIN businesses biz
                ON biz.id = b.business_id
            LEFT JOIN clients c
                ON c.id = b.client_id
            WHERE b.client_id = ?
              AND COALESCE(b.archived, 0) = 0
              AND LOWER(COALESCE(b.status, '')) IN ('confirmed', 'cancelled')
            ORDER BY b.id ASC
            """,
            (client_id,),
        )

        bookings = cursor.fetchall()

    finally:
        conn.close()

    for booking_row in bookings:
        try:
            notification_ctx = get_booking_notification_context(dict(booking_row))
            send_booking_status_changed_emails(notification_ctx, booking_row["status"])
        except Exception as exc:
            print(f"[MAIL][VERIFY][PENDING_STATUS] Błąd dla booking_id={booking_row['id']}: {exc}")


# =========================================================
# CLOSED DAYS
# =========================================================

def is_closed_day(date_str: str, business_id: int | None = None) -> bool:
    conn = get_connection()
    cursor = conn.cursor()

    try:
        if business_id is not None:
            cursor.execute(
                """
                SELECT id
                FROM closed_days
                WHERE closed_date = ?
                  AND business_id = ?
                LIMIT 1
                """,
                (date_str, business_id),
            )
        else:
            cursor.execute(
                """
                SELECT id
                FROM closed_days
                WHERE closed_date = ?
                LIMIT 1
                """,
                (date_str,),
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
            employee_ids,
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
            employee_ids,
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


def ensure_column(cursor, table_name, column_name, column_sql):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]

    if column_name not in columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_sql}"
        )

def get_booking_status_label(status):
    normalized = (status or "").strip().lower()

    labels = {
        "new": "Nowa",
        "confirmed": "Potwierdzona",
        "cancelled": "Anulowana",
        "completed": "Zrealizowana",
        "no_show": "Nieobecność",
        "archived": "Archiwalna",
    }

    return labels.get(normalized, status or "—")


def get_available_custom_booking_slots(cursor, business_id, employee_id, booking_date, duration_minutes):
    from datetime import datetime, timedelta

    try:
        selected_date = datetime.strptime(booking_date, "%Y-%m-%d").date()
    except ValueError:
        return []

    day_keys = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    day_key = day_keys[selected_date.weekday()]

    closed_day = cursor.execute("""
        SELECT id
        FROM closed_days
        WHERE business_id = ?
          AND closed_date = ?
        LIMIT 1
    """, (business_id, booking_date)).fetchone()

    if closed_day:
        return []

    time_off = cursor.execute("""
        SELECT id
        FROM employee_time_off
        WHERE business_id = ?
          AND employee_id = ?
          AND date_from <= ?
          AND date_to >= ?
        LIMIT 1
    """, (business_id, employee_id, booking_date, booking_date)).fetchone()

    if time_off:
        return []

    exception = cursor.execute("""
        SELECT is_day_off, start_time, end_time
        FROM employee_schedule_exceptions
        WHERE business_id = ?
          AND employee_id = ?
          AND exception_date = ?
        LIMIT 1
    """, (business_id, employee_id, booking_date)).fetchone()

    if exception:
        if int(exception["is_day_off"] or 0) == 1:
            return []

        work_start = exception["start_time"]
        work_end = exception["end_time"]
    else:
        schedule = cursor.execute("""
            SELECT enabled, start_time, end_time
            FROM employee_work_schedule
            WHERE business_id = ?
              AND employee_id = ?
              AND day_key = ?
            LIMIT 1
        """, (business_id, employee_id, day_key)).fetchone()

        if not schedule or int(schedule["enabled"] or 0) != 1:
            return []

        work_start = schedule["start_time"]
        work_end = schedule["end_time"]

    if not work_start or not work_end:
        return []

    settings = cursor.execute("""
        SELECT slot_interval_minutes
        FROM business_settings
        WHERE business_id = ?
        LIMIT 1
    """, (business_id,)).fetchone()

    slot_interval = 30
    if settings and settings["slot_interval_minutes"]:
        try:
            slot_interval = int(settings["slot_interval_minutes"])
        except ValueError:
            slot_interval = 30

    if slot_interval <= 0:
        slot_interval = 30

    day_start = datetime.strptime(f"{booking_date} {work_start}", "%Y-%m-%d %H:%M")
    day_end = datetime.strptime(f"{booking_date} {work_end}", "%Y-%m-%d %H:%M")

    existing_bookings = cursor.execute("""
        SELECT
            b.booking_time,
            COALESCE(b.custom_service_duration, s.duration_minutes, 30) AS duration_minutes
        FROM bookings b
        LEFT JOIN services s ON s.id = b.service_id
        WHERE b.business_id = ?
          AND b.employee_id = ?
          AND b.booking_date = ?
          AND COALESCE(b.archived, 0) = 0
          AND b.status NOT IN ('cancelled')
    """, (business_id, employee_id, booking_date)).fetchall()

    busy_ranges = []

    for booking in existing_bookings:
        booking_time = booking["booking_time"]
        booking_duration = booking["duration_minutes"] or 30

        try:
            booking_duration = int(booking_duration)
        except ValueError:
            booking_duration = 30

        if not booking_time:
            continue

        busy_start = datetime.strptime(f"{booking_date} {booking_time}", "%Y-%m-%d %H:%M")
        busy_end = busy_start + timedelta(minutes=booking_duration)

        busy_ranges.append((busy_start, busy_end))

    slots = []
    current = day_start

    while current + timedelta(minutes=duration_minutes) <= day_end:
        candidate_start = current
        candidate_end = current + timedelta(minutes=duration_minutes)

        is_busy = False

        for busy_start, busy_end in busy_ranges:
            overlaps = candidate_start < busy_end and candidate_end > busy_start
            if overlaps:
                is_busy = True
                break

        if not is_busy:
            slots.append(candidate_start.strftime("%H:%M"))

        current += timedelta(minutes=slot_interval)

    return slots


def get_or_create_custom_service_id(cursor, business_id):
    service = cursor.execute("""
        SELECT id
        FROM services
        WHERE business_id = ?
          AND name = ?
        LIMIT 1
    """, (business_id, "Usługa niestandardowa")).fetchone()

    if service:
        return service["id"]

    cursor.execute("""
        INSERT INTO services (
            business_id,
            name,
            service_group,
            duration_minutes,
            price,
            active
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        business_id,
        "Usługa niestandardowa",
        "System",
        30,
        "0 PLN",
        0
    ))

    return cursor.lastrowid    

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
            (employee_id, day_key),
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
            (employee_id, date_str),
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
            (employee_id, date_str),
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


def get_client_by_phone_or_email(business_id, phone=None, email=None):
    normalized_phone = (phone or "").strip()
    normalized_email = (email or "").strip().lower()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        if normalized_phone:
            cursor.execute(
                """
                SELECT *
                FROM clients
                WHERE business_id = ?
                  AND phone = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (business_id, normalized_phone),
            )
            row = cursor.fetchone()
            if row:
                return row

        if normalized_email:
            cursor.execute(
                """
                SELECT *
                FROM clients
                WHERE business_id = ?
                  AND LOWER(COALESCE(email, '')) = ?
                ORDER BY id ASC
                LIMIT 1
                """,
                (business_id, normalized_email),
            )
            row = cursor.fetchone()
            if row:
                return row

        return None

    finally:
        conn.close()


def get_or_create_client(
    business_id,
    full_name,
    phone=None,
    email=None,
    privacy_consent=0,
    marketing_consent=0,
    consent_source=None,
    consent_timestamp=None,
):
    full_name = (full_name or "").strip()
    phone = (phone or "").strip()
    email = (email or "").strip()
    consent_source = (consent_source or "").strip() or None
    consent_timestamp = (consent_timestamp or "").strip() or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not full_name:
        return None

    existing_client = get_client_by_phone_or_email(
        business_id=business_id,
        phone=phone,
        email=email,
    )

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
                  AND business_id = ?
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
                    business_id,
                ),
            )
            conn.commit()
            return existing_client["id"]

        cursor.execute(
            """
            INSERT INTO clients (
                business_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
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
            ),
        )

        conn.commit()
        return cursor.lastrowid

    except Exception as e:
        conn.rollback()
        print("Błąd get_or_create_client:", e)
        return None

    finally:
        conn.close()

import re

def parse_money_value(value):
    if not value:
        return 0.0

    value = str(value).lower()

    # usuń waluty i spacje
    value = value.replace("pln", "").replace("zł", "")
    value = value.replace(",", ".").strip()

    # 🔥 wyciągnij pierwszą liczbę z tekstu
    match = re.search(r"\d+(\.\d+)?", value)

    if match:
        try:
            return float(match.group())
        except:
            return 0.0

    return 0.0


def format_pln(value):
    try:
        value = float(value or 0)
    except (TypeError, ValueError):
        value = 0

    if value.is_integer():
        return f"{int(value)} PLN"

    return f"{value:.2f}".replace(".", ",") + " PLN"


def get_analytics_period_dates(period):
    today = datetime.now().date()

    period = (period or "30").strip().lower()

    if period == "today":
        start_date = today
        end_date = today
        label = "Dzisiaj"
    elif period == "7":
        start_date = today - timedelta(days=6)
        end_date = today
        label = "Ostatnie 7 dni"
    elif period == "90":
        start_date = today - timedelta(days=89)
        end_date = today
        label = "Ostatnie 90 dni"
    elif period == "year":
        start_date = today.replace(month=1, day=1)
        end_date = today
        label = "Cały rok"
    else:
        start_date = today - timedelta(days=29)
        end_date = today
        label = "Ostatnie 30 dni"

    return {
        "period": period,
        "label": label,
        "start_date": start_date.strftime("%Y-%m-%d"),
        "end_date": end_date.strftime("%Y-%m-%d"),
    }


def get_analytics_summary(business_id, period):
    period_data = get_analytics_period_dates(period)
    start_date = period_data["start_date"]
    end_date = period_data["end_date"]

    chart_map = {}
    current_date = datetime.strptime(start_date, "%Y-%m-%d").date()
    final_date = datetime.strptime(end_date, "%Y-%m-%d").date()

    while current_date <= final_date:
        key = current_date.strftime("%Y-%m-%d")
        chart_map[key] = {
            "label": current_date.strftime("%d.%m"),
            "bookings": 0,
            "revenue": 0.0,
        }
        current_date += timedelta(days=1)

    weekday_labels = [
        "Poniedziałek",
        "Wtorek",
        "Środa",
        "Czwartek",
        "Piątek",
        "Sobota",
        "Niedziela",
    ]

    weekday_revenue_map = {label: 0.0 for label in weekday_labels}
    visits_weekday_map = {label: 0 for label in weekday_labels}
    visits_hour_map = {}

    visits_status_map = {
        "completed": 0,
        "cancelled": 0,
        "no_show": 0,
        "confirmed": 0,
        "new": 0,
    }

    service_stats = {}
    employee_stats = {}
    hour_stats = {}
    client_stats = {}
    all_services_map = {}
    visits_history = []

    conn = get_connection()
    cursor = conn.cursor()

    try:
        booking_columns_rows = cursor.execute("PRAGMA table_info(bookings)").fetchall()
        booking_columns = [row["name"] for row in booking_columns_rows]

        client_columns_rows = cursor.execute("PRAGMA table_info(clients)").fetchall()
        client_columns = [row["name"] for row in client_columns_rows]

        service_columns_rows = cursor.execute("PRAGMA table_info(services)").fetchall()
        service_columns = [row["name"] for row in service_columns_rows]

        employee_columns_rows = cursor.execute("PRAGMA table_info(employees)").fetchall()
        employee_columns = [row["name"] for row in employee_columns_rows]

        def booking_has_col(name):
            return name in booking_columns

        def has_col(name):
            return name in client_columns

        def service_has_col(name):
            return name in service_columns

        def employee_has_col(name):
            return name in employee_columns

        client_name_sql = "'Klient bez nazwy'"
        if has_col("full_name"):
            client_name_sql = "COALESCE(c.full_name, '')"
        elif has_col("client_name"):
            client_name_sql = "COALESCE(c.client_name, '')"
        elif has_col("name"):
            client_name_sql = "COALESCE(c.name, '')"
        elif has_col("first_name") and has_col("last_name"):
            client_name_sql = "TRIM(COALESCE(c.first_name, '') || ' ' || COALESCE(c.last_name, ''))"
        elif has_col("first_name"):
            client_name_sql = "COALESCE(c.first_name, '')"
        elif has_col("last_name"):
            client_name_sql = "COALESCE(c.last_name, '')"
        elif has_col("email"):
            client_name_sql = "COALESCE(c.email, '')"

        client_phone_sql = "''"
        if has_col("phone"):
            client_phone_sql = "COALESCE(c.phone, '')"
        elif has_col("phone_number"):
            client_phone_sql = "COALESCE(c.phone_number, '')"
        elif has_col("telephone"):
            client_phone_sql = "COALESCE(c.telephone, '')"
        elif has_col("mobile"):
            client_phone_sql = "COALESCE(c.mobile, '')"
        elif has_col("client_phone"):
            client_phone_sql = "COALESCE(c.client_phone, '')"

        service_duration_sql = "s.duration_minutes" if service_has_col("duration_minutes") else "0"
        service_active_sql = "s.active" if service_has_col("active") else "1"

        service_name_select_sql = "s.name"
        service_price_select_sql = "s.price"
        service_duration_select_sql = service_duration_sql

        if booking_has_col("custom_service_name"):
            service_name_select_sql = "COALESCE(NULLIF(b.custom_service_name, ''), s.name)"

        if booking_has_col("custom_service_price"):
            service_price_select_sql = "COALESCE(NULLIF(b.custom_service_price, ''), s.price)"

        if booking_has_col("custom_service_duration"):
            service_duration_select_sql = f"COALESCE(b.custom_service_duration, {service_duration_sql})"

        employee_name_sql = "COALESCE(e.full_name, '—')"
        if employee_has_col("full_name"):
            employee_name_sql = "COALESCE(e.full_name, '—')"
        elif employee_has_col("name"):
            employee_name_sql = "COALESCE(e.name, '—')"
        elif employee_has_col("first_name") and employee_has_col("last_name"):
            employee_name_sql = "TRIM(COALESCE(e.first_name, '') || ' ' || COALESCE(e.last_name, ''))"
        elif employee_has_col("first_name"):
            employee_name_sql = "COALESCE(e.first_name, '—')"

        rows = cursor.execute(f"""
            SELECT
                b.id AS booking_id,
                b.client_id,
                b.booking_date,
                b.booking_time,
                LOWER(COALESCE(b.status, '')) AS status,

                s.id AS service_id,
                {service_name_select_sql} AS service_name,
                {service_price_select_sql} AS service_price,
                {service_duration_select_sql} AS service_duration_minutes,
                {service_active_sql} AS service_active,

                e.id AS employee_id,
                {employee_name_sql} AS employee_name,

                {client_name_sql} AS client_name,
                c.email AS client_email,
                {client_phone_sql} AS client_phone

            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN clients c ON c.id = b.client_id

            WHERE b.business_id = ?
              AND COALESCE(b.archived, 0) = 1
              AND b.booking_date BETWEEN ? AND ?

            ORDER BY b.booking_date ASC, b.booking_time ASC, b.id ASC
        """, (business_id, start_date, end_date)).fetchall()

        today_iso = datetime.now().strftime("%Y-%m-%d")

        future_rows = cursor.execute(f"""
            SELECT
                b.id AS booking_id,
                b.client_id,
                b.booking_date,
                b.booking_time,
                LOWER(COALESCE(b.status, '')) AS status,

                s.id AS service_id,
                {service_name_select_sql} AS service_name,
                {service_price_select_sql} AS service_price,

                e.id AS employee_id,
                {employee_name_sql} AS employee_name,

                {client_name_sql} AS client_name,
                c.email AS client_email,
                {client_phone_sql} AS client_phone

            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN clients c ON c.id = b.client_id

            WHERE b.business_id = ?
              AND COALESCE(b.archived, 0) = 0
              AND b.booking_date >= ?

            ORDER BY b.booking_date ASC, b.booking_time ASC, b.id ASC
        """, (business_id, today_iso)).fetchall()

        all_clients = cursor.execute(f"""
            SELECT
                id,
                {client_name_sql.replace("c.", "")} AS client_name,
                email,
                created_at
            FROM clients
            WHERE business_id = ?
        """, (business_id,)).fetchall()

        future_booking_rows = cursor.execute("""
            SELECT DISTINCT client_id
            FROM bookings
            WHERE business_id = ?
              AND COALESCE(archived, 0) = 0
              AND booking_date >= ?
              AND client_id IS NOT NULL
        """, (business_id, today_iso)).fetchall()

        if service_has_col("business_id"):
            all_services_rows = cursor.execute(f"""
                SELECT
                    id,
                    name,
                    price,
                    {service_duration_sql.replace("s.", "")} AS duration_minutes,
                    {service_active_sql.replace("s.", "")} AS active
                FROM services
                WHERE business_id = ?
                   OR business_id IS NULL
                ORDER BY name ASC
            """, (business_id,)).fetchall()
        else:
            all_services_rows = cursor.execute(f"""
                SELECT
                    id,
                    name,
                    price,
                    {service_duration_sql.replace("s.", "")} AS duration_minutes,
                    {service_active_sql.replace("s.", "")} AS active
                FROM services
                ORDER BY name ASC
            """).fetchall()

    finally:
        conn.close()

    for service in all_services_rows:
        service_id = service["id"]
        all_services_map[service_id] = {
            "id": service_id,
            "name": service["name"] or "—",
            "price": parse_money_value(service["price"]),
            "duration_minutes": int(service["duration_minutes"] or 0),
            "active": int(service["active"] or 0),
        }

    total_bookings = len(rows)
    completed = 0
    no_show = 0
    cancelled = 0

    total_revenue = 0.0
    no_show_lost = 0.0
    cancelled_lost = 0.0

    active_clients = set()

    def get_status_display(status):
        labels = {
            "new": ("Nowa", "is-neutral"),
            "confirmed": ("Potwierdzona", "is-ok"),
            "completed": ("Zrealizowana", "is-ok"),
            "cancelled": ("Anulowana", "is-warn"),
            "no_show": ("Nieobecność", "is-err"),
            "archived": ("Archiwalna", "is-neutral"),
        }
        return labels.get(status, (status or "—", "is-neutral"))

    for row in rows:
        status = row["status"]
        booking_date = row["booking_date"]
        booking_time = row["booking_time"] or ""
        price = parse_money_value(row["service_price"])

        if booking_date in chart_map:
            chart_map[booking_date]["bookings"] += 1

        if status in visits_status_map:
            visits_status_map[status] += 1

        try:
            weekday_index = datetime.strptime(booking_date, "%Y-%m-%d").weekday()
            weekday_label = weekday_labels[weekday_index]
            visits_weekday_map[weekday_label] += 1
        except Exception:
            pass

        if booking_time:
            hour = booking_time[:2]
            visits_hour_map.setdefault(hour, 0)
            visits_hour_map[hour] += 1

        status_label, status_class = get_status_display(status)

        visit_date_display = "—"
        if booking_date:
            try:
                visit_date_display = datetime.strptime(booking_date, "%Y-%m-%d").strftime("%d.%m.%Y")
            except Exception:
                visit_date_display = booking_date

        visits_history.append({
            "date": visit_date_display,
            "time": booking_time or "—",
            "client_name": (row["client_name"] or "").strip() or "Klient bez nazwy",
            "service_name": row["service_name"] or "—",
            "employee_name": row["employee_name"] or "—",
            "status_label": status_label,
            "status_class": status_class,
        })

        if row["client_id"]:
            active_clients.add(row["client_id"])

        service_name_for_stats = row["service_name"] or "—"
        service_id = row["service_id"] or 0
        service_key = f"{service_id}:{service_name_for_stats}"

        service_stats.setdefault(service_key, {
            "id": service_id,
            "name": service_name_for_stats,
            "price": price,
            "duration_minutes": int(row["service_duration_minutes"] or 0),
            "active": int(row["service_active"] or 0),
            "visits_count": 0,
            "completed_count": 0,
            "cancelled_count": 0,
            "no_show_count": 0,
            "count": 0,
            "revenue": 0.0,
            "lost_revenue": 0.0,
        })

        service_stats[service_key]["visits_count"] += 1

        if status == "completed":
            service_stats[service_key]["completed_count"] += 1
            service_stats[service_key]["count"] += 1
            service_stats[service_key]["revenue"] += price
        elif status == "cancelled":
            service_stats[service_key]["cancelled_count"] += 1
            service_stats[service_key]["lost_revenue"] += price
        elif status == "no_show":
            service_stats[service_key]["no_show_count"] += 1
            service_stats[service_key]["lost_revenue"] += price

        employee_id = row["employee_id"]

        if employee_id:
            employee_stats.setdefault(employee_id, {
                "id": employee_id,
                "name": row["employee_name"] or "—",
                "visits": 0,
                "completed": 0,
                "cancelled": 0,
                "no_show": 0,
                "revenue": 0.0,
                "lost_revenue": 0.0,
            })

            employee_stats[employee_id]["visits"] += 1

            if status == "completed":
                employee_stats[employee_id]["completed"] += 1
                employee_stats[employee_id]["revenue"] += price
            elif status == "cancelled":
                employee_stats[employee_id]["cancelled"] += 1
                employee_stats[employee_id]["lost_revenue"] += price
            elif status == "no_show":
                employee_stats[employee_id]["no_show"] += 1
                employee_stats[employee_id]["lost_revenue"] += price

        if status == "completed":
            completed += 1
            total_revenue += price

            if booking_date in chart_map:
                chart_map[booking_date]["revenue"] += price

            try:
                weekday_index = datetime.strptime(booking_date, "%Y-%m-%d").weekday()
                weekday_label = weekday_labels[weekday_index]
                weekday_revenue_map[weekday_label] += price
            except Exception:
                pass

            if booking_time:
                hour = booking_time[:2]
                hour_stats.setdefault(hour, {
                    "hour": hour,
                    "count": 0,
                    "revenue": 0.0,
                })
                hour_stats[hour]["count"] += 1
                hour_stats[hour]["revenue"] += price

            client_id = row["client_id"]

            if client_id:
                client_name = (row["client_name"] or "").strip()
                client_email = (row["client_email"] or "").strip()
                client_phone = (row["client_phone"] or "").strip()

                if not client_name:
                    client_name = client_email or client_phone or "Klient bez nazwy"

                client_stats.setdefault(client_id, {
                    "id": client_id,
                    "name": client_name,
                    "email": client_email,
                    "phone": client_phone,
                    "visits_count": 0,
                    "total_spent_raw": 0.0,
                    "last_visit_date": None,
                })

                client_stats[client_id]["visits_count"] += 1
                client_stats[client_id]["total_spent_raw"] += price

                if not client_stats[client_id]["last_visit_date"]:
                    client_stats[client_id]["last_visit_date"] = booking_date
                elif booking_date > client_stats[client_id]["last_visit_date"]:
                    client_stats[client_id]["last_visit_date"] = booking_date

        elif status == "no_show":
            no_show += 1
            no_show_lost += price

        elif status == "cancelled":
            cancelled += 1
            cancelled_lost += price

    measured_visits = completed + no_show + cancelled
    avg_visit = total_revenue / completed if completed else 0
    no_show_rate = (no_show / measured_visits * 100) if measured_visits else 0
    cancelled_rate = (cancelled / measured_visits * 100) if measured_visits else 0

    top_services = sorted(service_stats.values(), key=lambda x: x["revenue"], reverse=True)[:10]

    top_employees_raw = sorted(
        employee_stats.values(),
        key=lambda x: x["revenue"],
        reverse=True
    )

    top_employees = top_employees_raw[:8]
    top_hours = sorted(hour_stats.values(), key=lambda x: x["revenue"], reverse=True)[:12]

    best_day = "—"
    best_day_val = 0.0

    if weekday_revenue_map:
        best_day, best_day_val = max(weekday_revenue_map.items(), key=lambda x: x[1])
        if best_day_val <= 0:
            best_day = "—"

    total_clients_count = len(all_clients)
    clients_without_email_count = 0
    new_clients_count = 0

    for client in all_clients:
        email = (client["email"] or "").strip()
        if not email:
            clients_without_email_count += 1

        created_at = client["created_at"] or ""
        if created_at[:10] >= start_date and created_at[:10] <= end_date:
            new_clients_count += 1

    future_client_ids = {
        row["client_id"]
        for row in future_booking_rows
        if row["client_id"]
    }

    clients_with_future_booking_count = len(future_client_ids)

    vip_clients_count = 0
    regular_clients_count = 0
    at_risk_clients_count = 0
    inactive_clients_count = 0
    clients_to_recover_count = 0
    returning_clients_count = 0

    today_date = datetime.strptime(end_date, "%Y-%m-%d").date()
    top_clients = []

    for client in client_stats.values():
        visits_count = int(client["visits_count"] or 0)
        total_spent_raw = float(client["total_spent_raw"] or 0)
        last_visit_date = client["last_visit_date"]

        days_since_last_visit = None
        if last_visit_date:
            try:
                last_date = datetime.strptime(last_visit_date, "%Y-%m-%d").date()
                days_since_last_visit = (today_date - last_date).days
            except Exception:
                days_since_last_visit = None

        if visits_count > 1:
            returning_clients_count += 1

        if total_spent_raw >= 1000 or visits_count >= 8:
            status_label = "VIP"
            status_class = "is-ok"
            vip_clients_count += 1
        elif visits_count >= 3:
            status_label = "Regularny"
            status_class = "is-ok"
            regular_clients_count += 1
        elif days_since_last_visit is not None and days_since_last_visit >= 60:
            status_label = "Do odzyskania"
            status_class = "is-err"
            clients_to_recover_count += 1
        elif days_since_last_visit is not None and days_since_last_visit >= 30:
            status_label = "Zagrożony"
            status_class = "is-warn"
            at_risk_clients_count += 1
        elif days_since_last_visit is not None and days_since_last_visit >= 14:
            status_label = "Nieaktywny"
            status_class = "is-neutral"
            inactive_clients_count += 1
        else:
            status_label = "Aktywny"
            status_class = "is-ok"

        last_visit_display = "—"
        if last_visit_date:
            try:
                last_visit_display = datetime.strptime(last_visit_date, "%Y-%m-%d").strftime("%d.%m.%Y")
            except Exception:
                last_visit_display = last_visit_date

        top_clients.append({
            "name": client["name"],
            "phone": client["phone"],
            "email": client["email"],
            "visits_count": visits_count,
            "total_spent": format_pln(total_spent_raw),
            "total_spent_raw": total_spent_raw,
            "last_visit_date": last_visit_display,
            "status_label": status_label,
            "status_class": status_class,
        })

    top_clients = sorted(top_clients, key=lambda x: x["total_spent_raw"], reverse=True)[:100]

    services_count = len(all_services_map)
    active_services_count = sum(1 for item in all_services_map.values() if item["active"] == 1)
    inactive_services_count = max(services_count - active_services_count, 0)

    avg_service_price_raw = (
        sum(item["price"] for item in all_services_map.values()) / services_count
        if services_count else 0
    )

    avg_service_duration = (
        round(sum(item["duration_minutes"] for item in all_services_map.values()) / services_count)
        if services_count else 0
    )

    services_summary = []

    for service in service_stats.values():
        visits_count = int(service["visits_count"] or 0)
        completed_count = int(service["completed_count"] or 0)
        cancelled_count = int(service["cancelled_count"] or 0)
        no_show_count_service = int(service["no_show_count"] or 0)

        measured_count = completed_count + cancelled_count + no_show_count_service

        cancel_rate = (cancelled_count / measured_count * 100) if measured_count else 0
        no_show_rate_service = (no_show_count_service / measured_count * 100) if measured_count else 0

        services_summary.append({
            "name": service["name"],
            "visits_count": visits_count,
            "completed_count": completed_count,
            "cancelled_count": cancelled_count,
            "no_show_count": no_show_count_service,
            "revenue": format_pln(service["revenue"]),
            "revenue_raw": service["revenue"],
            "lost_revenue": format_pln(service["lost_revenue"]),
            "cancel_rate": round(cancel_rate, 1),
            "no_show_rate": round(no_show_rate_service, 1),
            "avg_price": format_pln(service["revenue"] / completed_count if completed_count else 0),
            "duration_minutes": service["duration_minutes"],
            "active": service["active"],
        })

    services_summary = sorted(
        services_summary,
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:100]

    top_services_by_revenue = sorted(
        services_summary,
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:10]

    top_services_by_visits = sorted(
        services_summary,
        key=lambda x: x["visits_count"],
        reverse=True
    )[:10]

    top_services_by_cancel_rate = sorted(
        services_summary,
        key=lambda x: x["cancel_rate"],
        reverse=True
    )[:10]

    top_services_by_no_show_rate = sorted(
        services_summary,
        key=lambda x: x["no_show_rate"],
        reverse=True
    )[:10]

    top_service_by_visits_name = top_services_by_visits[0]["name"] if top_services_by_visits else "—"
    top_service_by_revenue_name = top_services_by_revenue[0]["name"] if top_services_by_revenue else "—"

    total_visits_for_distribution = total_bookings if total_bookings else 0

    visits_by_weekday = []

    for label in weekday_labels:
        count = visits_weekday_map.get(label, 0)
        percent = (count / total_visits_for_distribution * 100) if total_visits_for_distribution else 0

        visits_by_weekday.append({
            "label": label,
            "count": count,
            "percent": round(percent, 1),
        })

    visits_by_weekday = sorted(visits_by_weekday, key=lambda x: x["count"], reverse=True)

    visits_by_hour = []

    for hour, count in visits_hour_map.items():
        percent = (count / total_visits_for_distribution * 100) if total_visits_for_distribution else 0

        visits_by_hour.append({
            "hour": hour,
            "count": count,
            "percent": round(percent, 1),
        })

    visits_by_hour = sorted(visits_by_hour, key=lambda x: x["count"], reverse=True)[:12]

    visits_status_chart_labels = ["Zrealizowane", "Anulowane", "Nieobecności", "Potwierdzone", "Nowe"]
    visits_status_chart_values = [
        visits_status_map["completed"],
        visits_status_map["cancelled"],
        visits_status_map["no_show"],
        visits_status_map["confirmed"],
        visits_status_map["new"],
    ]

    visits_history = list(reversed(visits_history))[:100]

    employees_summary = []

    for employee in employee_stats.values():
        visits = int(employee["visits"] or 0)
        completed_count = int(employee["completed"] or 0)
        cancelled_count = int(employee["cancelled"] or 0)
        no_show_count_employee = int(employee["no_show"] or 0)
        revenue = float(employee["revenue"] or 0)

        avg_employee_visit = revenue / completed_count if completed_count else 0
        load_percent = (completed_count / visits * 100) if visits else 0
        no_show_employee_rate = (no_show_count_employee / visits * 100) if visits else 0
        cancel_employee_rate = (cancelled_count / visits * 100) if visits else 0

        employees_summary.append({
            "name": employee["name"],
            "visits": visits,
            "completed": completed_count,
            "cancelled": cancelled_count,
            "no_show": no_show_count_employee,
            "revenue": format_pln(revenue),
            "revenue_raw": revenue,
            "avg_visit": format_pln(avg_employee_visit),
            "avg_visit_raw": avg_employee_visit,
            "load_percent": round(load_percent, 1),
            "no_show_rate": round(no_show_employee_rate, 1),
            "cancel_rate": round(cancel_employee_rate, 1),
            "lost_revenue": format_pln(employee["lost_revenue"]),
            "lost_revenue_raw": float(employee["lost_revenue"] or 0),
        })

    employees_summary = sorted(
        employees_summary,
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:100]

    best_employee = employees_summary[0] if employees_summary else None

    employee_by_no_show = sorted(
        employees_summary,
        key=lambda x: x["no_show"],
        reverse=True
    )

    employee_by_efficiency = sorted(
        employees_summary,
        key=lambda x: x["avg_visit_raw"],
        reverse=True
    )

    worst_employee_no_show = (
        employee_by_no_show[0]["name"]
        if employee_by_no_show and employee_by_no_show[0]["no_show"] > 0
        else "—"
    )

    best_employee_efficiency = (
        employee_by_efficiency[0]["avg_visit"]
        if employee_by_efficiency and employee_by_efficiency[0]["avg_visit_raw"] > 0
        else "—"
    )

    future_bookings_count = 0
    future_revenue_raw = 0.0
    confirmed_future_revenue_raw = 0.0
    unconfirmed_future_revenue_raw = 0.0

    future_weekday_map = {
        label: {"count": 0, "revenue": 0.0}
        for label in weekday_labels
    }

    future_hour_map = {}
    future_employee_map = {}
    future_service_map = {}
    upcoming_revenue_items = []

    for row in future_rows:
        status = row["status"] or ""
        booking_date = row["booking_date"] or ""
        booking_time = row["booking_time"] or ""
        price = parse_money_value(row["service_price"])

        if status in ["cancelled", "no_show", "completed", "archived"]:
            continue

        future_bookings_count += 1
        future_revenue_raw += price

        if status == "confirmed":
            confirmed_future_revenue_raw += price
        else:
            unconfirmed_future_revenue_raw += price

        try:
            weekday_index = datetime.strptime(booking_date, "%Y-%m-%d").weekday()
            weekday_label = weekday_labels[weekday_index]
            future_weekday_map[weekday_label]["count"] += 1
            future_weekday_map[weekday_label]["revenue"] += price
        except Exception:
            pass

        if booking_time:
            hour = booking_time[:2]
            future_hour_map.setdefault(hour, {
                "hour": hour,
                "count": 0,
                "revenue": 0.0,
            })

            future_hour_map[hour]["count"] += 1
            future_hour_map[hour]["revenue"] += price

        employee_name = row["employee_name"] or "—"

        future_employee_map.setdefault(employee_name, {
            "name": employee_name,
            "count": 0,
            "revenue": 0.0,
        })

        future_employee_map[employee_name]["count"] += 1
        future_employee_map[employee_name]["revenue"] += price

        service_name = row["service_name"] or "—"

        future_service_map.setdefault(service_name, {
            "name": service_name,
            "count": 0,
            "revenue": 0.0,
        })

        future_service_map[service_name]["count"] += 1
        future_service_map[service_name]["revenue"] += price

        status_label, status_class = get_status_display(status)

        date_display = booking_date
        if booking_date:
            try:
                date_display = datetime.strptime(booking_date, "%Y-%m-%d").strftime("%d.%m.%Y")
            except Exception:
                pass

        client_name = (row["client_name"] or "").strip()
        client_email = (row["client_email"] or "").strip()
        client_phone = (row["client_phone"] or "").strip()

        if not client_name:
            client_name = client_email or client_phone or "Klient bez nazwy"

        upcoming_revenue_items.append({
            "date": date_display or "—",
            "time": booking_time or "—",
            "client_name": client_name,
            "service_name": service_name,
            "employee_name": employee_name,
            "status_label": status_label,
            "status_class": status_class,
            "revenue": format_pln(price),
            "revenue_raw": price,
        })

    future_revenue_by_weekday = []

    for label in weekday_labels:
        item = future_weekday_map[label]
        future_revenue_by_weekday.append({
            "label": label,
            "count": item["count"],
            "revenue": format_pln(item["revenue"]),
            "revenue_raw": item["revenue"],
        })

    future_revenue_by_weekday = sorted(
        future_revenue_by_weekday,
        key=lambda x: x["revenue_raw"],
        reverse=True
    )

    future_revenue_by_hour = sorted(
        [
            {
                "hour": item["hour"],
                "count": item["count"],
                "revenue": format_pln(item["revenue"]),
                "revenue_raw": item["revenue"],
            }
            for item in future_hour_map.values()
        ],
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:12]

    future_revenue_by_employee = sorted(
        [
            {
                "name": item["name"],
                "count": item["count"],
                "revenue": format_pln(item["revenue"]),
                "revenue_raw": item["revenue"],
            }
            for item in future_employee_map.values()
        ],
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:12]

    future_revenue_by_service = sorted(
        [
            {
                "name": item["name"],
                "count": item["count"],
                "revenue": format_pln(item["revenue"]),
                "revenue_raw": item["revenue"],
            }
            for item in future_service_map.values()
        ],
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:12]

    upcoming_revenue_items = sorted(
        upcoming_revenue_items,
        key=lambda x: x["revenue_raw"],
        reverse=True
    )[:100]

    insights = []
    alerts = []

    if total_bookings == 0:
        insights.append({
            "title": "Brak danych w wybranym okresie",
            "description": "W tym zakresie nie ma jeszcze archiwalnych wizyt do analizy.",
            "label": "info",
            "type": "",
        })
    else:
        if best_day != "—":
            insights.append({
                "title": f"Najlepszy dzień: {best_day}",
                "description": f"Ten dzień wygenerował największy przychód: {format_pln(best_day_val)}.",
                "label": "trend",
                "type": "is-ok",
            })

        if top_services_by_revenue:
            service = top_services_by_revenue[0]
            insights.append({
                "title": f"Najbardziej dochodowa usługa: {service['name']}",
                "description": f"Usługa wygenerowała {service['revenue']} przychodu w wybranym okresie.",
                "label": "usługa",
                "type": "is-ok",
            })

        if best_employee:
            insights.append({
                "title": f"Najlepszy pracownik: {best_employee['name']}",
                "description": f"Pracownik wygenerował {best_employee['revenue']} przychodu.",
                "label": "zespół",
                "type": "is-ok",
            })

        if avg_visit > 0:
            insights.append({
                "title": "Średnia wartość wizyty",
                "description": f"Jedna zakończona wizyta daje średnio {format_pln(avg_visit)} przychodu.",
                "label": "PLN",
                "type": "",
            })

        if returning_clients_count > 0:
            insights.append({
                "title": "Klienci wracający",
                "description": f"{returning_clients_count} klientów miało więcej niż jedną zakończoną wizytę.",
                "label": "retencja",
                "type": "is-ok",
            })

        if clients_to_recover_count > 0:
            insights.append({
                "title": "Klienci do odzyskania",
                "description": f"{clients_to_recover_count} klientów dawno nie wróciło. To dobra grupa do kontaktu.",
                "label": "CRM",
                "type": "is-warn",
            })

    if future_bookings_count > 0:
        insights.append({
            "title": "Przyszły przychód w kalendarzu",
            "description": f"Obecne przyszłe rezerwacje mają szacowaną wartość {format_pln(future_revenue_raw)}.",
            "label": "prognoza",
            "type": "is-ok",
        })

    if no_show_rate >= 20:
        alerts.append({
            "title": "Wysoki poziom nieobecności",
            "description": f"No-show rate wynosi {round(no_show_rate, 1)}%. Warto przypominać klientom o wizytach.",
            "level": "ALERT",
        })

    if cancelled_rate >= 25:
        alerts.append({
            "title": "Dużo anulowanych wizyt",
            "description": f"Anulacje stanowią {round(cancelled_rate, 1)}% rozliczanych wizyt.",
            "level": "UWAGA",
        })

    if no_show_lost + cancelled_lost > 0:
        alerts.append({
            "title": "Utracony przychód",
            "description": f"Szacowana strata z no-show i anulacji to {format_pln(no_show_lost + cancelled_lost)}.",
            "level": "PLN",
        })

    if clients_without_email_count > 0:
        alerts.append({
            "title": "Brak adresów e-mail",
            "description": f"{clients_without_email_count} klientów nie ma adresu e-mail w bazie.",
            "level": "CRM",
        })

    if future_bookings_count == 0:
        alerts.append({
            "title": "Brak przyszłych rezerwacji",
            "description": "W kalendarzu nie ma obecnie zapisanych przyszłych wizyt.",
            "level": "RUCH",
        })

    if unconfirmed_future_revenue_raw > 0:
        alerts.append({
            "title": "Przychód do potwierdzenia",
            "description": f"{format_pln(unconfirmed_future_revenue_raw)} znajduje się w rezerwacjach nowych lub niepotwierdzonych.",
            "level": "UWAGA",
        })

    if employees_summary:
        low_load_employees = [
            emp for emp in employees_summary
            if emp["visits"] >= 3 and emp["load_percent"] < 40
        ]

        if low_load_employees:
            alerts.append({
                "title": "Niskie obłożenie części zespołu",
                "description": f"{low_load_employees[0]['name']} ma niskie obłożenie: {low_load_employees[0]['load_percent']}%.",
                "level": "ZESPÓŁ",
            })

    chart_items = list(chart_map.values())

    return {
        "analytics_period": period_data["period"],
        "analytics_period_label": period_data["label"],
        "analytics_start_date": start_date,
        "analytics_end_date": end_date,

        "total_bookings": total_bookings,
        "completed_bookings": completed,
        "total_revenue": format_pln(total_revenue),
        "average_visit_value": format_pln(avg_visit),

        "no_show_count": no_show,
        "no_show_rate": round(no_show_rate, 1),
        "cancelled_count": cancelled,

        "new_clients_count": new_clients_count,
        "returning_clients_count": returning_clients_count,
        "active_clients_count": len(active_clients),

        "total_clients_count": total_clients_count,
        "vip_clients_count": vip_clients_count,
        "regular_clients_count": regular_clients_count,
        "at_risk_clients_count": at_risk_clients_count,
        "inactive_clients_count": inactive_clients_count,
        "clients_to_recover_count": clients_to_recover_count,
        "clients_with_future_booking_count": clients_with_future_booking_count,
        "clients_without_email_count": clients_without_email_count,
        "top_clients": top_clients,

        "top_service_name": top_services[0]["name"] if top_services else "—",
        "top_service_count": top_services[0]["count"] if top_services else 0,
        "top_service_revenue": format_pln(top_services[0]["revenue"]) if top_services else format_pln(0),

        "top_employee_name": best_employee["name"] if best_employee else "—",
        "top_employee_bookings": best_employee["completed"] if best_employee else 0,
        "top_employee_revenue": best_employee["revenue"] if best_employee else format_pln(0),
        "best_employee_revenue": best_employee["revenue"] if best_employee else format_pln(0),
        "worst_employee_no_show": worst_employee_no_show,
        "best_employee_efficiency": best_employee_efficiency,
        "employees_summary": employees_summary,

        "best_day_name": best_day,
        "best_day_revenue": format_pln(best_day_val),

        "no_show_lost": format_pln(no_show_lost),
        "cancelled_lost": format_pln(cancelled_lost),
        "lost_revenue": format_pln(no_show_lost + cancelled_lost),

        "top_services_revenue": [
            {
                "name": item["name"],
                "count": item["count"],
                "revenue": format_pln(item["revenue"]),
            }
            for item in top_services
        ],

        "employee_revenue": [
            {
                "name": item["name"],
                "bookings": item["completed"],
                "revenue": format_pln(item["revenue"]),
            }
            for item in top_employees
        ],

        "revenue_by_hour": [
            {
                "hour": item["hour"],
                "count": item["count"],
                "revenue": format_pln(item["revenue"]),
            }
            for item in top_hours
        ],

        "services_count": services_count,
        "active_services_count": active_services_count,
        "inactive_services_count": inactive_services_count,
        "avg_service_price": format_pln(avg_service_price_raw),
        "avg_service_duration": f"{avg_service_duration} min" if avg_service_duration else "—",

        "services_summary": services_summary,

        "top_service_by_visits_name": top_service_by_visits_name,
        "top_service_by_revenue_name": top_service_by_revenue_name,

        "top_services_by_revenue": top_services_by_revenue,
        "top_services_by_visits": top_services_by_visits,
        "top_services_by_cancel_rate": top_services_by_cancel_rate,
        "top_services_by_no_show_rate": top_services_by_no_show_rate,

        "top_services_revenue_chart_labels": [item["name"] for item in top_services_by_revenue],
        "top_services_revenue_chart_values": [round(item["revenue_raw"], 2) for item in top_services_by_revenue],

        "top_services_visits_chart_labels": [item["name"] for item in top_services_by_visits],
        "top_services_visits_chart_values": [item["visits_count"] for item in top_services_by_visits],

        "services_cancel_rate_chart_labels": [item["name"] for item in top_services_by_cancel_rate],
        "services_cancel_rate_chart_values": [item["cancel_rate"] for item in top_services_by_cancel_rate],

        "services_no_show_rate_chart_labels": [item["name"] for item in top_services_by_no_show_rate],
        "services_no_show_rate_chart_values": [item["no_show_rate"] for item in top_services_by_no_show_rate],

        "visits_by_weekday": visits_by_weekday,
        "visits_by_hour": visits_by_hour,
        "visits_history": visits_history,

        "visits_status_chart_labels": visits_status_chart_labels,
        "visits_status_chart_values": visits_status_chart_values,

        "weekday_revenue_labels": list(weekday_revenue_map.keys()),
        "weekday_revenue_values": [
            round(value, 2)
            for value in weekday_revenue_map.values()
        ],

        "bookings_chart_labels": [item["label"] for item in chart_items],
        "bookings_chart_values": [item["bookings"] for item in chart_items],
        "revenue_chart_values": [round(item["revenue"], 2) for item in chart_items],

        "future_bookings_count": future_bookings_count,
        "future_revenue": format_pln(future_revenue_raw),
        "confirmed_future_revenue": format_pln(confirmed_future_revenue_raw),
        "unconfirmed_future_revenue": format_pln(unconfirmed_future_revenue_raw),
        "future_revenue_by_weekday": future_revenue_by_weekday,
        "future_revenue_by_hour": future_revenue_by_hour,
        "future_revenue_by_employee": future_revenue_by_employee,
        "future_revenue_by_service": future_revenue_by_service,
        "upcoming_revenue_items": upcoming_revenue_items,

        "insights": insights,
        "alerts": alerts,
    }


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


def get_booking_side_images(business_id=None, side=None, only_active=True, limit=None):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        query = """
            SELECT *
            FROM booking_side_images
            WHERE 1 = 1
        """
        params = []

        if business_id is not None:
            query += " AND business_id = ?"
            params.append(business_id)

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


def fetch_booking_notification_data(booking_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                b.id,
                b.business_id,
                b.client_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.status,

                COALESCE(NULLIF(b.custom_service_name, ''), s.name) AS service_name,

                e.full_name AS employee_name,
                e.email AS employee_email,

                -- ustawienia firmy (KLUCZOWE DO MAILI)
                bs.company_name,
                bs.company_address,
                bs.contact_phone,
                bs.contact_email AS salon_email,
                bs.website_url,
                bs.privacy_policy_url,

                biz.name AS business_name,

                COALESCE(c.email_verified, 0) AS client_email_verified

            FROM bookings b

            LEFT JOIN services s
                ON s.id = b.service_id

            LEFT JOIN employees e
                ON e.id = b.employee_id

            LEFT JOIN business_settings bs
                ON bs.business_id = b.business_id

            LEFT JOIN businesses biz
                ON biz.id = b.business_id

            LEFT JOIN clients c
                ON c.id = b.client_id

            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,),
        )

        row = cursor.fetchone()
        return dict(row) if row else None

    finally:
        conn.close()


def send_password_reset_email(user_email, reset_link, user_full_name=None):
    user_name = (user_full_name or "").strip() or "Użytkowniku"

    subject = "Reset hasła do panelu administratora"

    body = dedent(f"""
        Dzień dobry {user_name},

        Otrzymaliśmy prośbę o zresetowanie hasła do panelu administratora.

        W celu ustawienia nowego hasła, kliknij w poniższy link:
        {reset_link}

        Jeżeli ta prośba nie została zainicjowana przez Ciebie, po prostu zignoruj tę wiadomość.

        Link do resetu hasła jest jednorazowy i wygasa po czasie ustawionym w systemie.

        Pozdrawiamy,
        Zespół Alifio
    """).strip()

    send_email_smtp(user_email, subject, body)


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

        user = get_user_by_email(email)

        if not user or int(user["is_active"]) != 1:
            flash("Nieprawidłowy e-mail lub hasło.", "error")
            return render_template(
                "admin_login.html",
                page_title="Logowanie administratora",
                settings=settings
            )

        if not verify_password(password, user["password_hash"]):
            flash("Nieprawidłowy e-mail lub hasło.", "error")
            return render_template(
                "admin_login.html",
                page_title="Logowanie administratora",
                settings=settings
            )

        if user["role"] not in ("super_admin", "client_admin", "staff"):
            flash("To konto nie ma dostępu do panelu.", "error")
            return render_template(
                "admin_login.html",
                page_title="Logowanie administratora",
                settings=settings
            )

        login_admin(user, remember_me=remember_me)
        update_user_last_login(user["id"])

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
        user = get_user_by_email(email)

        if user and int(user["is_active"]) == 1:
            try:
                token = create_password_reset_token(user["id"])
                reset_link = url_for("reset_password", token=token, _external=True)

                send_password_reset_email(
                    user_email=user["email"],
                    reset_link=reset_link,
                    user_full_name=(user["full_name"] or "")
                )

            except Exception as e:
                print("Błąd wysyłki maila resetu hasła:", e)

        flash("Jeśli konto istnieje, link do resetu hasła został wysłany na adres e-mail.", "success")
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

        update_user_password(token_row["user_id"], password, must_change_password=0)
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
    user = get_user_by_id(session["admin_id"])

    if not user:
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

        if not verify_password(current_password, user["password_hash"]):
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

        update_user_password(user["id"], new_password, must_change_password=0)
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
          AND LOWER(TRIM(COALESCE(s.service_group, ''))) != 'niestandardowe'
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
            "employee_photo_path": row["employee_photo_path"] or "",
            "employee_photo_url": media_url(row["employee_photo_path"]) if row["employee_photo_path"] else ""
        })

    business_id = 1

    if settings and "business_id" in settings.keys() and settings["business_id"]:
        business_id = settings["business_id"]

    booking_left_images = get_booking_side_images(
        business_id=business_id,
        side="left",
        only_active=True
    )
    booking_right_images = get_booking_side_images(
        business_id=business_id,
        side="right",
        only_active=True
    )

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
        booking_right_images=booking_right_images,
        turnstile_enabled=TURNSTILE_ENABLED,
        turnstile_site_key=TURNSTILE_SITE_KEY
    )


@app.route("/dziekujemy")
def booking_thank_you():
    settings = get_settings()
    booking_summary = session.pop("booking_thank_you_data", None)

    if not booking_summary:
        return redirect(url_for("booking"))

    return render_template(
        "thank_you.html",
        page_title="Dziękujemy za rezerwację",
        settings=settings,
        booking_summary=booking_summary
    )


@app.route("/lista-oczekujacych-dziekujemy")
def waitlist_thank_you():
    settings = get_settings()
    waitlist_summary = session.pop("waitlist_thank_you_data", None)

    if not waitlist_summary:
        return redirect(url_for("booking"))

    return render_template(
        "waitlist_thank_you.html",
        page_title="Dziękujemy za zgłoszenie",
        settings=settings,
        waitlist_summary=waitlist_summary
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
    



# =========================================================
# ALIFIO AI CONCIERGE — BACKEND CLEAN FLOW
# =========================================================

def ai_normalize_text(value):
    value = (value or "").strip().lower()
    value = unicodedata.normalize("NFKD", value)
    value = "".join(ch for ch in value if not unicodedata.combining(ch))
    value = re.sub(r"[^a-z0-9ąćęłńóśźż\s-]", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def ai_get_public_business_id():
    settings = get_settings()

    if settings and "business_id" in settings.keys() and settings["business_id"]:
        return settings["business_id"]

    return 1


def ai_get_privacy_policy_url():
    settings = get_settings()

    if settings and "privacy_policy_url" in settings.keys():
        return (settings["privacy_policy_url"] or "").strip()

    return ""


def ai_text_confirms_privacy(value):
    text = ai_normalize_text(value)

    phrases = [
        "akceptuje",
        "akceptuje polityke prywatnosci",
        "zgadzam sie",
        "zgadzam sie na polityke prywatnosci",
        "potwierdzam",
        "tak akceptuje",
        "tak zgadzam sie",
    ]

    return any(phrase in text for phrase in phrases)


def ai_text_confirms_marketing(value):
    text = ai_normalize_text(value)

    negative = [
        "nie",
        "nie zgadzam sie",
        "nie chce",
        "bez marketingu",
        "odmawiam",
    ]

    positive = [
        "tak",
        "zgadzam sie",
        "akceptuje",
        "chce",
    ]

    if any(item == text or item in text for item in negative):
        return False

    if any(item == text or item in text for item in positive):
        return True

    return None


def ai_extract_time_from_message(value):
    text = (value or "").strip()

    match = re.search(r"\b([01]?\d|2[0-3])[:.]([0-5]\d)\b", text)
    if match:
        return f"{int(match.group(1)):02d}:{int(match.group(2)):02d}"

    match = re.search(r"\b([01]?\d|2[0-3])\b", text)
    if match:
        return f"{int(match.group(1)):02d}:00"

    return ""


def ai_extract_date_from_message(value):
    text = (value or "").strip().lower()
    today = datetime.now().date()

    if "jutro" in text:
        return (today + timedelta(days=1)).strftime("%Y-%m-%d")

    if "dzisiaj" in text or "dziś" in text:
        return today.strftime("%Y-%m-%d")

    match = re.search(r"\b(\d{1,2})[.\-/](\d{1,2})(?:[.\-/](\d{2,4}))?\b", text)

    if not match:
        return ""

    day = int(match.group(1))
    month = int(match.group(2))
    year_raw = match.group(3)

    if year_raw:
        year = int(year_raw)
        if year < 100:
            year += 2000
    else:
        year = today.year

    try:
        return datetime(year, month, day).strftime("%Y-%m-%d")
    except ValueError:
        return ""


def ai_extract_email_from_message(value):
    match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", value or "")

    if match:
        return match.group(0).strip().lower()

    return ""


def ai_extract_phone_from_message(value):
    cleaned = re.sub(r"[^\d+]", "", value or "")

    if len(cleaned) >= 7:
        return cleaned

    return ""


def ai_get_services_catalog():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                s.id AS service_id,
                s.name AS service_name,
                s.duration_minutes,
                s.price,
                s.service_group,
                e.id AS employee_id,
                e.full_name AS employee_name,
                e.role AS employee_role
            FROM services s
            JOIN service_employees se ON se.service_id = s.id
            JOIN employees e ON e.id = se.employee_id
            WHERE COALESCE(s.active, 1) = 1
              AND COALESCE(e.active, 1) = 1
            ORDER BY s.service_group, s.name, e.full_name
        """)
        rows = cursor.fetchall()
    finally:
        conn.close()

    services_map = {}

    for row in rows:
        service_id = row["service_id"]

        if service_id not in services_map:
            services_map[service_id] = {
                "id": service_id,
                "name": row["service_name"] or "",
                "duration_minutes": row["duration_minutes"] or 30,
                "price": row["price"] or "",
                "group": row["service_group"] or "",
                "employees": []
            }

        services_map[service_id]["employees"].append({
            "id": row["employee_id"],
            "name": row["employee_name"] or "",
            "role": row["employee_role"] or ""
        })

    return list(services_map.values())


def ai_find_service_by_id(services, service_id):
    try:
        service_id = int(service_id)
    except (TypeError, ValueError):
        return None

    for service in services:
        if int(service["id"]) == service_id:
            return service

    return None


def ai_find_employee_by_id(service, employee_id):
    if not service:
        return None

    try:
        employee_id = int(employee_id)
    except (TypeError, ValueError):
        return None

    for employee in service.get("employees", []):
        if int(employee["id"]) == employee_id:
            return employee

    return None


def ai_find_service(services, query):
    query_norm = ai_normalize_text(query)

    if not query_norm:
        return None

    for service in services:
        name_norm = ai_normalize_text(service.get("name"))

        if query_norm == name_norm:
            return service

    for service in services:
        name_norm = ai_normalize_text(service.get("name"))

        if query_norm in name_norm or name_norm in query_norm:
            return service

    query_words = set(query_norm.split())
    best_service = None
    best_score = 0

    for service in services:
        name_words = set(ai_normalize_text(service.get("name")).split())
        score = len(query_words.intersection(name_words))

        if score > best_score:
            best_score = score
            best_service = service

    return best_service if best_score > 0 else None


def ai_find_employee(service, query):
    if not service:
        return None

    query_norm = ai_normalize_text(query)

    if not query_norm:
        return None

    employees = service.get("employees", [])

    for employee in employees:
        name_norm = ai_normalize_text(employee.get("name"))

        if query_norm == name_norm:
            return employee

    for employee in employees:
        name_norm = ai_normalize_text(employee.get("name"))

        if query_norm in name_norm or name_norm in query_norm:
            return employee

    query_words = set(query_norm.split())
    best_employee = None
    best_score = 0

    for employee in employees:
        name_words = set(ai_normalize_text(employee.get("name")).split())
        score = len(query_words.intersection(name_words))

        if score > best_score:
            best_score = score
            best_employee = employee

    return best_employee if best_score > 0 else None


def ai_time_to_minutes(value):
    value = (value or "").strip()

    if not value:
        return None

    try:
        hour, minute = value.split(":")
        return int(hour) * 60 + int(minute)
    except Exception:
        return None


def ai_filter_slots_by_time(slots, time_from=None, time_to=None):
    if not slots:
        return []

    from_minutes = ai_time_to_minutes(time_from)
    to_minutes = ai_time_to_minutes(time_to)

    filtered = []

    for slot in slots:
        slot_minutes = ai_time_to_minutes(slot)

        if slot_minutes is None:
            continue

        if from_minutes is not None and slot_minutes < from_minutes:
            continue

        if to_minutes is not None and slot_minutes > to_minutes:
            continue

        filtered.append(slot)

    return filtered


def ai_group_services_for_reply(services):
    grouped = {}

    for service in services:
        group_name = (service.get("group") or "").strip() or "Pozostałe"
        grouped.setdefault(group_name, []).append(service)

    return grouped


def ai_services_reply(services):
    grouped = ai_group_services_for_reply(services)

    if not grouped:
        return "Nie widzę obecnie aktywnych usług do rezerwacji.", []

    lines = ["Wybierz grupę lub konkretną usługę:"]
    suggestions = []

    for group_name, group_services in grouped.items():
        lines.append("")
        lines.append(f"{group_name}:")

        for service in group_services:
            price = service.get("price") or "cena do potwierdzenia"
            lines.append(f"• {service['name']} — {price}")
            suggestions.append(service["name"])

    return "\n".join(lines), suggestions[:12]


def ai_employees_reply(service):
    employees = service.get("employees", [])

    if not employees:
        return f"Usługa „{service['name']}” nie ma przypisanego aktywnego pracownika.", []

    lines = [f"Dla usługi „{service['name']}” możesz wybrać pracownika:"]
    suggestions = []

    for employee in employees:
        role = (employee.get("role") or "").strip()
        label = employee["name"] if not role else f"{employee['name']} — {role}"

        lines.append(f"• {label}")
        suggestions.append(employee["name"])

    lines.append("")
    lines.append("Którego pracownika wybierasz?")

    return "\n".join(lines), suggestions


def ai_format_slots_reply(service, employee, date_iso, slots):
    try:
        date_display = datetime.strptime(date_iso, "%Y-%m-%d").strftime("%d.%m.%Y")
    except Exception:
        date_display = date_iso

    if not slots:
        return (
            f"Nie widzę wolnych godzin dla usługi „{service['name']}” "
            f"u {employee['name']} w dniu {date_display}. "
            "Podaj inny dzień albo wybierz innego pracownika."
        ), []

    shown_slots = slots[:10]

    return (
        f"Dla usługi „{service['name']}” u {employee['name']} "
        f"w dniu {date_display} dostępne są godziny:\n\n"
        + "\n".join([f"• {slot}" for slot in shown_slots])
        + "\n\nKtórą godzinę wybierasz?"
    ), shown_slots


def ai_clear_context_if_requested(message):
    text = ai_normalize_text(message)

    phrases = [
        "zacznij od nowa",
        "od nowa",
        "reset",
        "wyczysc",
        "anuluj",
        "zmien usluge",
    ]

    return any(phrase in text for phrase in phrases)


def ai_save_conversation(message, reply):
    conversation = session.get("alifio_ai_conversation", [])

    conversation.append({
        "role": "user",
        "content": message
    })

    conversation.append({
        "role": "assistant",
        "content": reply
    })

    session["alifio_ai_conversation"] = conversation[-10:]
    session.modified = True


def ai_create_booking_from_context(context):
    business_id = ai_get_public_business_id()

    service_id = context.get("service_id")
    employee_id = context.get("employee_id")
    booking_date = (context.get("date_iso") or "").strip()
    booking_time = (context.get("booking_time") or "").strip()

    client_name = (context.get("client_name") or "").strip()
    client_phone = (context.get("client_phone") or "").strip()
    client_email = (context.get("client_email") or "").strip()

    privacy_consent = 1 if context.get("privacy_consent_confirmed") else 0
    marketing_consent = 1 if context.get("marketing_consent_confirmed") else 0

    if not service_id or not employee_id or not booking_date or not booking_time:
        return {
            "success": False,
            "message": "Brakuje danych terminu."
        }

    if not client_name:
        return {
            "success": False,
            "message": "Do rezerwacji potrzebuję imienia i nazwiska."
        }

    if not client_phone:
        return {
            "success": False,
            "message": "Do rezerwacji potrzebuję numeru telefonu."
        }

    if not privacy_consent:
        return {
            "success": False,
            "message": "Przed zapisem potrzebuję akceptacji polityki prywatności."
        }

    available_slots = get_available_slots_for_day(service_id, employee_id, booking_date)

    if booking_time not in available_slots:
        return {
            "success": False,
            "message": "Wybrany termin nie jest już dostępny."
        }

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    client_id = get_or_create_client(
        business_id=business_id,
        full_name=client_name,
        phone=client_phone,
        email=client_email,
        privacy_consent=privacy_consent,
        marketing_consent=marketing_consent,
        consent_source="ai_concierge",
        consent_timestamp=now_str
    )

    if not client_id:
        return {
            "success": False,
            "message": "Nie udało się utworzyć lub odnaleźć klienta."
        }

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO bookings (
                business_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            business_id,
            service_id,
            employee_id,
            client_id,
            client_name,
            client_email or None,
            client_phone,
            booking_date,
            booking_time,
            "Rezerwacja utworzona przez ALIFIO AI Concierge",
            "new",
            privacy_consent,
            marketing_consent,
            now_str
        ))

        booking_id = cursor.lastrowid
        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd ai_create_booking_from_context:", e)

        return {
            "success": False,
            "message": "Nie udało się zapisać rezerwacji."
        }

    finally:
        conn.close()

    try:
        send_booking_internal_notifications(booking_id)
    except Exception as e:
        print("Błąd wysyłki maili wewnętrznych AI booking:", e)

    if client_email:
        try:
            cancel_token = create_booking_cancel_token(booking_id)
            cancel_url = url_for("cancel_booking_from_link", token=cancel_token, _external=True)
            send_booking_verification_email(booking_id, cancel_url=cancel_url)
        except Exception as e:
            print("Błąd wysyłki maila AI booking:", e)

    return {
        "success": True,
        "booking_id": booking_id,
        "message": "Rezerwacja została zapisana."
    }


@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    normalized = ai_normalize_text(message)

    if not message:
        return jsonify({
            "success": False,
            "reply": "Napisz wiadomość, a pomogę wybrać usługę i termin.",
            "slots": [],
            "suggestions": [],
            "pending_context": {}
        }), 400

    services = ai_get_services_catalog()

    if ai_clear_context_if_requested(message):
        session.pop("alifio_ai_pending_context", None)
        session.pop("alifio_ai_conversation", None)

        reply, suggestions = ai_services_reply(services)

        return jsonify({
            "success": True,
            "reply": reply,
            "slots": [],
            "suggestions": suggestions,
            "pending_context": {}
        })

    context = session.get("alifio_ai_pending_context", {}) or {}
    stage = context.get("stage") or "service"

    selected_service = ai_find_service_by_id(services, context.get("service_id"))
    selected_employee = ai_find_employee_by_id(selected_service, context.get("employee_id"))

    # ETAP: USŁUGA
    if not selected_service:
        found_service = ai_find_service(services, message)

        if found_service:
            selected_service = found_service
            context["service_id"] = selected_service["id"]
            context["service_name"] = selected_service["name"]

            employees = selected_service.get("employees", [])

            if len(employees) == 1:
                selected_employee = employees[0]
                context["employee_id"] = selected_employee["id"]
                context["employee_name"] = selected_employee["name"]
                context["stage"] = "date"

                reply = (
                    f"Wybrano usługę „{selected_service['name']}” "
                    f"u {selected_employee['name']}.\n\n"
                    "Na jaki dzień mam sprawdzić wolne godziny?"
                )

                session["alifio_ai_pending_context"] = context
                ai_save_conversation(message, reply)

                return jsonify({
                    "success": True,
                    "reply": reply,
                    "slots": [],
                    "suggestions": [],
                    "pending_context": context
                })

            reply, suggestions = ai_employees_reply(selected_service)
            context["stage"] = "employee"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": suggestions,
                "pending_context": context
            })

        reply, suggestions = ai_services_reply(services)
        context["stage"] = "service"
        session["alifio_ai_pending_context"] = context
        ai_save_conversation(message, reply)

        return jsonify({
            "success": True,
            "reply": reply,
            "slots": [],
            "suggestions": suggestions,
            "pending_context": context
        })

    # ETAP: PRACOWNIK
    if not selected_employee:
        found_employee = ai_find_employee(selected_service, message)

        if found_employee:
            selected_employee = found_employee
            context["employee_id"] = selected_employee["id"]
            context["employee_name"] = selected_employee["name"]
            context["stage"] = "date"

            reply = (
                f"Wybrano usługę „{selected_service['name']}” "
                f"u {selected_employee['name']}.\n\n"
                "Na jaki dzień mam sprawdzić wolne godziny?"
            )

            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": [],
                "pending_context": context
            })

        reply, suggestions = ai_employees_reply(selected_service)
        context["stage"] = "employee"
        session["alifio_ai_pending_context"] = context
        ai_save_conversation(message, reply)

        return jsonify({
            "success": True,
            "reply": reply,
            "slots": [],
            "suggestions": suggestions,
            "pending_context": context
        })

    # ETAP: DATA
    if not context.get("date_iso"):
        date_iso = ai_extract_date_from_message(message)

        if date_iso:
            context["date_iso"] = date_iso
            context["stage"] = "time"
        else:
            reply = "Na jaki dzień mam sprawdzić dostępne godziny? Podaj datę np. 12.05.2026 albo napisz „jutro”."

            context["stage"] = "date"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": [],
                "pending_context": context
            })

    # SLOTY
    try:
        available_slots = get_available_slots_for_day(
            context["service_id"],
            context["employee_id"],
            context["date_iso"]
        )

        slots = ai_filter_slots_by_time(available_slots)

    except Exception as e:
        print("Błąd sprawdzania slotów AI:", e)

        reply = "Nie udało się sprawdzić godzin. Podaj datę jeszcze raz, np. 12.05.2026."

        context.pop("date_iso", None)
        context["stage"] = "date"
        session["alifio_ai_pending_context"] = context
        ai_save_conversation(message, reply)

        return jsonify({
            "success": True,
            "reply": reply,
            "slots": [],
            "suggestions": [],
            "pending_context": context
        })

    # ETAP: GODZINA
    if not context.get("booking_time"):
        time_value = ai_extract_time_from_message(message)

        if time_value and time_value in slots:
            context["booking_time"] = time_value
            context["stage"] = "client_name"
        elif time_value and time_value not in slots:
            reply, suggestions = ai_format_slots_reply(selected_service, selected_employee, context["date_iso"], slots)
            reply = "Ta godzina nie jest dostępna.\n\n" + reply

            context["stage"] = "time"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": slots[:10],
                "suggestions": suggestions,
                "pending_context": context
            })
        else:
            reply, suggestions = ai_format_slots_reply(selected_service, selected_employee, context["date_iso"], slots)

            context["stage"] = "time"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": slots[:10],
                "suggestions": suggestions,
                "pending_context": context
            })

    # ETAP: IMIĘ I NAZWISKO
    if not context.get("client_name"):
        if stage == "client_name" and len(message.split()) >= 2:
            context["client_name"] = message.strip()
            context["stage"] = "client_phone"
        else:
            reply = "Podaj proszę imię i nazwisko do rezerwacji."

            context["stage"] = "client_name"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": [],
                "pending_context": context
            })

    # ETAP: TELEFON
    if not context.get("client_phone"):
        phone = ai_extract_phone_from_message(message)

        if stage == "client_phone" and phone:
            context["client_phone"] = phone
            context["stage"] = "client_email"
        else:
            reply = "Dziękuję. Podaj proszę numer telefonu do rezerwacji."

            context["stage"] = "client_phone"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": [],
                "pending_context": context
            })

    # ETAP: EMAIL
    if not context.get("client_email") and not context.get("client_email_skipped"):
        email = ai_extract_email_from_message(message)

        if stage == "client_email" and email:
            context["client_email"] = email
            context["stage"] = "privacy"
        elif stage == "client_email" and ("bez maila" in normalized or "bez emaila" in normalized):
            context["client_email"] = ""
            context["client_email_skipped"] = True
            context["stage"] = "privacy"
        else:
            reply = "Podaj proszę adres e-mail. Jeśli klient nie chce podawać e-maila, napisz: „bez maila”."

            context["stage"] = "client_email"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": ["bez maila"],
                "pending_context": context
            })

    # ETAP: POLITYKA PRYWATNOŚCI
    if not context.get("privacy_consent_confirmed"):
        if stage == "privacy" and ai_text_confirms_privacy(message):
            context["privacy_consent_confirmed"] = True
            context["stage"] = "marketing"
        else:
            privacy_url = ai_get_privacy_policy_url()

            if privacy_url:
                reply = (
                    "Aby zapisać rezerwację, potrzebuję potwierdzenia akceptacji polityki prywatności.\n\n"
                    f"Polityka prywatności: {privacy_url}\n\n"
                    "Napisz: „Akceptuję politykę prywatności”."
                )
            else:
                reply = "Napisz: „Akceptuję politykę prywatności”."

            context["stage"] = "privacy"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": ["Akceptuję politykę prywatności"],
                "pending_context": context
            })

    # ETAP: MARKETING
    if not context.get("marketing_consent_answered"):
        marketing_result = ai_text_confirms_marketing(message)

        if stage == "marketing" and marketing_result is not None:
            context["marketing_consent_answered"] = True
            context["marketing_consent_confirmed"] = bool(marketing_result)
            context["stage"] = "save"
        else:
            reply = (
                "Zgoda marketingowa jest dobrowolna.\n\n"
                "Czy klient chce otrzymywać informacje marketingowe i promocyjne? "
                "Odpowiedz: „Tak” albo „Nie”."
            )

            context["stage"] = "marketing"
            session["alifio_ai_pending_context"] = context
            ai_save_conversation(message, reply)

            return jsonify({
                "success": True,
                "reply": reply,
                "slots": [],
                "suggestions": ["Tak", "Nie"],
                "pending_context": context
            })

    # ZAPIS
    result = ai_create_booking_from_context(context)

    if result.get("success"):
        try:
            date_display = datetime.strptime(context["date_iso"], "%Y-%m-%d").strftime("%d.%m.%Y")
        except Exception:
            date_display = context["date_iso"]

        reply = (
            "Rezerwacja została zapisana.\n\n"
            f"Usługa: {context.get('service_name')}\n"
            f"Pracownik: {context.get('employee_name')}\n"
            f"Termin: {date_display}, godz. {context.get('booking_time')}\n"
            f"Klient: {context.get('client_name')}\n"
            f"Telefon: {context.get('client_phone')}\n\n"
            "Dziękujemy."
        )

        session.pop("alifio_ai_pending_context", None)
        final_context = {}

    else:
        reply = result.get("message") or "Nie udało się zapisać rezerwacji."
        final_context = context

    ai_save_conversation(message, reply)

    return jsonify({
        "success": True,
        "reply": reply,
        "slots": [],
        "suggestions": [],
        "pending_context": final_context
    })




@app.route("/book", methods=["POST"])
def create_booking():
    service_id = request.form.get("service_id", type=int)
    employee_id = request.form.get("employee_id", type=int)

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()

    booking_date_raw = (request.form.get("booking_date") or "").strip()
    booking_date = normalize_text_date_to_db(booking_date_raw)
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

    settings = get_settings()
    business_id = (
        settings["business_id"]
        if settings and "business_id" in settings.keys() and settings["business_id"]
        else 1
    )

    client_id = get_or_create_client(
        business_id=business_id,
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
            SELECT
                id,
                email,
                COALESCE(email_verified, 0) AS email_verified
            FROM clients
            WHERE id = ?
              AND business_id = ?
            LIMIT 1
            """,
            (client_id, business_id)
        )
        client_row = cursor.fetchone()

        client_email_verified = 0
        if client_row:
            client_email_verified = int(client_row["email_verified"] or 0)

        cursor.execute(
            """
            SELECT name
            FROM services
            WHERE id = ?
            LIMIT 1
            """,
            (service_id,)
        )
        service_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT full_name
            FROM employees
            WHERE id = ?
            LIMIT 1
            """,
            (employee_id,)
        )
        employee_row = cursor.fetchone()

        cursor.execute(
            """
            INSERT INTO bookings (
                business_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
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

        booking_id = cursor.lastrowid
        conn.commit()

        cancel_token = create_booking_cancel_token(booking_id)
        cancel_url = url_for("cancel_booking_from_link", token=cancel_token, _external=True)

        try:
            send_booking_internal_notifications(booking_id)
        except Exception as e:
            print("Błąd wysyłki maili wewnętrznych dla bookingu:", e)

        if client_email and client_email_verified != 1:
            try:
                send_booking_verification_email(booking_id, cancel_url=cancel_url)
            except Exception as e:
                print("Błąd wysyłki maila weryfikacyjnego dla bookingu:", e)

        session["booking_thank_you_data"] = {
            "service_name": service_row["name"] if service_row else "",
            "employee_name": employee_row["full_name"] if employee_row else "",
            "booking_date": booking_date,
            "booking_time": booking_time,
            "client_email": client_email,
        }

    except Exception as e:
        conn.rollback()
        print("Błąd create_booking:", e)
        flash("Nie udało się zapisać rezerwacji. Spróbuj ponownie.", "error")
        return redirect(url_for("booking"))

    finally:
        conn.close()

    return redirect(url_for("booking_thank_you"))

# =========================================================
# ADMIN DASHBOARD / BOOKINGS
# =========================================================

@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_connection()
    cursor = conn.cursor()

    ensure_column(cursor, "bookings", "booking_type", "booking_type TEXT NOT NULL DEFAULT 'standard'")
    ensure_column(cursor, "bookings", "custom_service_name", "custom_service_name TEXT")
    ensure_column(cursor, "bookings", "custom_service_price", "custom_service_price TEXT")
    ensure_column(cursor, "bookings", "custom_service_duration", "custom_service_duration INTEGER")
    conn.commit()

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
            COALESCE(NULLIF(bookings.custom_service_name, ''), services.name) AS service_name,
            COALESCE(NULLIF(bookings.custom_service_price, ''), services.price) AS service_price,
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
            COALESCE(NULLIF(bookings.custom_service_name, ''), services.name) AS service_name,
            COALESCE(NULLIF(bookings.custom_service_price, ''), services.price) AS service_price,
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
            s.price AS service_price,
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
    new_status = (request.form.get("status") or "").strip().lower()

    allowed_statuses = ["new", "confirmed", "cancelled"]
    if new_status not in allowed_statuses:
        flash("Nieprawidłowy status.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                service_id,
                employee_id,
                booking_date,
                booking_time,
                status
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

        if previous_status == new_status:
            flash("Status rezerwacji nie zmienił się.", "info")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            UPDATE bookings
            SET status = ?
            WHERE id = ?
            """,
            (new_status, booking_id)
        )
        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd update_booking_status:", e)
        flash("Nie udało się zaktualizować statusu rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()

    # gdy termin został zwolniony, dopasuj pierwszą osobę z waitlisty
    if new_status == "cancelled" and previous_status != "cancelled":
        try:
            mark_first_waitlist_match_for_slot(
                booking_row["service_id"],
                booking_row["employee_id"],
                booking_row["booking_date"],
                booking_row["booking_time"]
            )
        except Exception as waitlist_error:
            print("Błąd dopasowania waitlisty po anulowaniu:", waitlist_error)

    # maile tylko dla przejść confirmed <-> cancelled
    # maile przy każdej realnej zmianie na confirmed lub cancelled
    should_send_status_emails = (
        new_status in ("confirmed", "cancelled")
        and previous_status != new_status
    )

    if should_send_status_emails:
        try:
            booking_data = fetch_booking_notification_data(booking_id)
            if booking_data:
                notification_ctx = get_booking_notification_context(booking_data)
                send_booking_status_changed_emails(notification_ctx, new_status)
        except Exception as mail_error:
            print("Błąd wysyłki maili po zmianie statusu rezerwacji:", mail_error)

    flash("Status rezerwacji został zaktualizowany.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/bookings/confirm-all-new", methods=["POST"])
@admin_required
def confirm_all_new_bookings():
    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    booking_ids = []

    try:
        cursor.execute(
            """
            SELECT id
            FROM bookings
            WHERE business_id = ?
              AND COALESCE(archived, 0) = 0
              AND LOWER(COALESCE(status, '')) = 'new'
            ORDER BY booking_date ASC, booking_time ASC, id ASC
            """,
            (business_id,)
        )

        booking_ids = [row["id"] for row in cursor.fetchall()]

        if not booking_ids:
            flash("Nie ma nowych rezerwacji do potwierdzenia.", "info")
            return redirect(url_for("admin_dashboard"))

        placeholders = ",".join(["?"] * len(booking_ids))

        cursor.execute(
            f"""
            UPDATE bookings
            SET status = 'confirmed'
            WHERE business_id = ?
              AND COALESCE(archived, 0) = 0
              AND LOWER(COALESCE(status, '')) = 'new'
              AND id IN ({placeholders})
            """,
            [business_id, *booking_ids]
        )

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd confirm_all_new_bookings:", e)
        flash("Nie udało się potwierdzić nowych rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()

    sent_count = 0

    for booking_id in booking_ids:
        try:
            booking_data = fetch_booking_notification_data(booking_id)

            if booking_data:
                notification_ctx = get_booking_notification_context(booking_data)
                send_booking_status_changed_emails(notification_ctx, "confirmed")
                sent_count += 1

        except Exception as mail_error:
            print(
                f"Błąd wysyłki maili po masowym potwierdzeniu booking_id={booking_id}:",
                mail_error
            )

    flash(
        f"Potwierdzono nowe rezerwacje: {len(booking_ids)}.<br>"
        f"Wysłano powiadomienia dla: {sent_count}.",
        "success"
    )

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



@app.route("/admin/bookings/hard/create", methods=["POST"])
@admin_required
def create_hard_booking():
    business_id = session.get("business_id", 1)

    booking_date_raw = (request.form.get("booking_date") or "").strip()
    booking_time_raw = (request.form.get("booking_time") or "").strip()

    booking_date = normalize_text_date_to_db(booking_date_raw)
    booking_time = normalize_text_time_value(booking_time_raw)

    employee_id = request.form.get("employee_id", type=int)

    service_id = request.form.get("service_id", type=int)
    custom_service_name = (request.form.get("service_name") or "").strip()

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()

    price = (request.form.get("price") or "").strip()
    duration_raw = (request.form.get("duration") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if not booking_date or not booking_time or not employee_id or not client_name:
        flash("Uzupełnij poprawnie datę, godzinę, pracownika i dane klienta.", "error")
        return redirect(url_for("admin_dashboard"))

    if not service_id and not custom_service_name:
        flash("Wybierz istniejącą usługę albo wpisz usługę niestandardową.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        duration = int(duration_raw) if duration_raw else 30
    except ValueError:
        duration = 30

    if duration <= 0:
        duration = 30

    if price:
        if "pln" not in price.lower() and "zł" not in price.lower():
            price = f"{price} PLN"
    else:
        price = "0 PLN"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    client_id = get_or_create_client(
        business_id=business_id,
        full_name=client_name,
        phone=client_phone,
        email=client_email,
        privacy_consent=0,
        marketing_consent=0,
        consent_source="hard_booking_admin",
        consent_timestamp=now_str
    )

    if not client_id:
        flash("Nie udało się utworzyć lub odnaleźć karty klienta.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        ensure_column(cursor, "bookings", "booking_type", "booking_type TEXT NOT NULL DEFAULT 'standard'")
        ensure_column(cursor, "bookings", "custom_service_name", "custom_service_name TEXT")
        ensure_column(cursor, "bookings", "custom_service_price", "custom_service_price TEXT")
        ensure_column(cursor, "bookings", "custom_service_duration", "custom_service_duration INTEGER")

        if service_id:
            selected_service = cursor.execute("""
                SELECT id, name, price, duration_minutes
                FROM services
                WHERE id = ?
                  AND active = 1
                LIMIT 1
            """, (service_id,)).fetchone()

            if not selected_service:
                conn.rollback()
                flash("Wybrana usługa nie istnieje albo jest nieaktywna.", "error")
                return redirect(url_for("admin_dashboard"))

            final_service_id = selected_service["id"]
            final_custom_service_name = None
            final_custom_service_price = None
            final_custom_service_duration = None

        else:
            final_service_id = get_or_create_custom_service_id(cursor, business_id)
            final_custom_service_name = custom_service_name
            final_custom_service_price = price
            final_custom_service_duration = duration

        cursor.execute("""
            INSERT INTO bookings (
                business_id,
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
                archived,
                booking_type,
                custom_service_name,
                custom_service_price,
                custom_service_duration,
                privacy_consent,
                marketing_consent,
                consents_created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            business_id,
            final_service_id,
            employee_id,
            client_id,
            client_name,
            client_email or None,
            client_phone or None,
            booking_date,
            booking_time,
            notes or None,
            "confirmed",
            0,
            "hard",
            final_custom_service_name,
            final_custom_service_price,
            final_custom_service_duration,
            0,
            0,
            now_str
        ))

        booking_id = cursor.lastrowid
        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd create_hard_booking:", e)
        flash("Nie udało się zapisać wymuszonej rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()

    try:
        send_booking_internal_notifications(booking_id)
    except Exception as mail_error:
        print("Błąd wysyłki maili wewnętrznych dla wymuszonej rezerwacji:", mail_error)

    try:
        booking_data = fetch_booking_notification_data(booking_id)
        if booking_data:
            notification_ctx = get_booking_notification_context(booking_data)
            send_booking_status_changed_emails(notification_ctx, "confirmed")
    except Exception as mail_error:
        print("Błąd wysyłki maili statusowych dla wymuszonej rezerwacji:", mail_error)

    if client_email:
        try:
            cancel_token = create_booking_cancel_token(booking_id)
            cancel_url = url_for("cancel_booking_from_link", token=cancel_token, _external=True)
            send_booking_verification_email(booking_id, cancel_url=cancel_url)
        except Exception as mail_error:
            print("Błąd wysyłki maila weryfikacyjnego dla wymuszonej rezerwacji:", mail_error)

    flash("Wymuszona rezerwacja została dodana.", "success")
    return redirect(url_for("admin_dashboard"))

# =========================================================
# ADMIN SERVICES
# =========================================================

@app.route("/admin/services")
@client_admin_required
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





@app.route("/admin/services/<int:service_id>/toggle", methods=["POST"])
@client_admin_required
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
@client_admin_required
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

@app.route("/admin/services/add", methods=["POST"])
@client_admin_required
def add_service():
    name = (request.form.get("name") or "").strip()
    service_group = (request.form.get("service_group") or "").strip()
    duration_minutes = request.form.get("duration_minutes", type=int)
    price = (request.form.get("price") or "").strip()
    employee_ids = request.form.getlist("employee_ids[]")

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    if not name:
        if is_ajax:
            return jsonify({"success": False, "message": "Podaj nazwę usługi."}), 400
        flash("Podaj nazwę usługi.", "error")
        return redirect(url_for("admin_services"))

    if not duration_minutes or duration_minutes < 5:
        if is_ajax:
            return jsonify({"success": False, "message": "Podaj poprawny czas trwania usługi."}), 400
        flash("Podaj poprawny czas trwania usługi.", "error")
        return redirect(url_for("admin_services"))

    valid_employee_ids = []

    for employee_id in employee_ids:
        try:
            employee_id_int = int(employee_id)

            if employee_id_int not in valid_employee_ids:
                valid_employee_ids.append(employee_id_int)

        except (TypeError, ValueError):
            continue

    if not valid_employee_ids:
        if is_ajax:
            return jsonify({
                "success": False,
                "message": "Wybierz co najmniej jednego pracownika dla usługi."
            }), 400

        flash("Wybierz co najmniej jednego pracownika dla usługi.", "error")
        return redirect(url_for("admin_services"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO services (
                name,
                service_group,
                duration_minutes,
                price,
                active
            )
            VALUES (?, ?, ?, ?, 1)
        """, (
            name,
            service_group or None,
            duration_minutes,
            price or None
        ))

        service_id = cursor.lastrowid

        for employee_id in valid_employee_ids:
            cursor.execute("""
                INSERT INTO service_employees (
                    service_id,
                    employee_id
                )
                VALUES (?, ?)
            """, (
                service_id,
                employee_id
            ))

        conn.commit()

        cursor.execute("""
            SELECT e.id, e.full_name
            FROM service_employees se
            JOIN employees e ON e.id = se.employee_id
            WHERE se.service_id = ?
            ORDER BY e.full_name ASC
        """, (service_id,))

        employee_rows = cursor.fetchall()

        service_data = {
            "id": service_id,
            "name": name,
            "service_group": service_group or "",
            "duration_minutes": duration_minutes,
            "price": price or "",
            "active": 1,
            "employee_ids_csv": ",".join(str(row["id"]) for row in employee_rows),
            "employee_names": [row["full_name"] for row in employee_rows],
        }

        if is_ajax:
            return jsonify({
                "success": True,
                "message": "Usługa została dodana.",
                "service": service_data
            })

        flash("Usługa została dodana.", "success")
        return redirect(url_for("admin_services"))

    except Exception as e:
        conn.rollback()
        print("Błąd add_service:", e)

        if is_ajax:
            return jsonify({
                "success": False,
                "message": "Nie udało się dodać usługi."
            }), 500

        flash("Nie udało się dodać usługi.", "error")
        return redirect(url_for("admin_services"))

    finally:
        conn.close()

@app.route("/admin/services/update", methods=["POST"])
@client_admin_required
def update_service():
    service_id = request.form.get("service_id")
    name = (request.form.get("name") or "").strip()
    service_group = (request.form.get("service_group") or "").strip()
    duration_minutes = (request.form.get("duration_minutes") or "").strip()
    price = (request.form.get("price") or "").strip()
    employee_ids = request.form.getlist("employee_ids[]")

    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    if not service_id:
        if is_ajax:
            return jsonify({"success": False, "message": "Nie wybrano usługi do edycji."}), 400
        flash("Nie wybrano usługi do edycji.", "error")
        return redirect(url_for("admin_services"))

    if not name:
        if is_ajax:
            return jsonify({"success": False, "message": "Nazwa usługi jest wymagana."}), 400
        flash("Nazwa usługi jest wymagana.", "error")
        return redirect(url_for("admin_services"))

    if not duration_minutes:
        if is_ajax:
            return jsonify({"success": False, "message": "Czas trwania usługi jest wymagany."}), 400
        flash("Czas trwania usługi jest wymagany.", "error")
        return redirect(url_for("admin_services"))

    try:
        service_id_int = int(service_id)
        duration_minutes_int = int(duration_minutes)
    except ValueError:
        if is_ajax:
            return jsonify({"success": False, "message": "Nieprawidłowe dane usługi."}), 400
        flash("Nieprawidłowe dane usługi.", "error")
        return redirect(url_for("admin_services"))

    if duration_minutes_int < 5:
        if is_ajax:
            return jsonify({"success": False, "message": "Czas trwania usługi musi wynosić co najmniej 5 minut."}), 400
        flash("Czas trwania usługi musi wynosić co najmniej 5 minut.", "error")
        return redirect(url_for("admin_services"))

    valid_employee_ids = []
    for employee_id in employee_ids:
        try:
            valid_employee_ids.append(int(employee_id))
        except (TypeError, ValueError):
            continue

    if not valid_employee_ids:
        if is_ajax:
            return jsonify({"success": False, "message": "Wybierz przynajmniej jednego pracownika dla usługi."}), 400
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

        cursor.execute(
            """
            SELECT e.id, e.full_name
            FROM service_employees se
            JOIN employees e ON e.id = se.employee_id
            WHERE se.service_id = ?
            ORDER BY e.full_name ASC
            """,
            (service_id_int,)
        )
        employee_rows = cursor.fetchall()

        service_data = {
            "id": service_id_int,
            "name": name,
            "service_group": service_group or "",
            "duration_minutes": duration_minutes_int,
            "price": price or "",
            "active": 1,
            "employee_ids_csv": ",".join(str(row["id"]) for row in employee_rows),
            "employee_names": [row["full_name"] for row in employee_rows],
        }

        if is_ajax:
            return jsonify({
                "success": True,
                "message": "Usługa została zaktualizowana.",
                "service": service_data
            })

        flash("Usługa została zaktualizowana.", "success")
        return redirect(url_for("admin_services"))

    except Exception as e:
        conn.rollback()
        print("Błąd update_service:", e)

        if is_ajax:
            return jsonify({"success": False, "message": "Nie udało się zaktualizować usługi."}), 500

        flash("Nie udało się zaktualizować usługi.", "error")
        return redirect(url_for("admin_services"))

    finally:
        conn.close()

        
# =========================================================
# ADMIN SETTINGS
# =========================================================

@app.route("/admin/settings")
@client_admin_required
def admin_settings():
    business_id = session.get("business_id", 1)
    admin_id = session.get("admin_id")
    current_role = session.get("admin_role")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        settings = cursor.execute(
            """
            SELECT *
            FROM business_settings
            WHERE business_id = ?
            LIMIT 1
            """,
            (business_id,)
        ).fetchone()

        if not settings:
            settings = cursor.execute(
                """
                SELECT *
                FROM business_settings
                WHERE id = 1
                LIMIT 1
                """
            ).fetchone()

        current_user = None
        if admin_id:
            current_user = cursor.execute(
                """
                SELECT id, email, role
                FROM users
                WHERE id = ?
                LIMIT 1
                """,
                (admin_id,)
            ).fetchone()

        employees = cursor.execute(
            """
            SELECT *
            FROM employees
            WHERE business_id = ?
            ORDER BY id DESC
            """,
            (business_id,)
        ).fetchall()

        closed_days = cursor.execute(
            """
            SELECT *
            FROM closed_days
            WHERE business_id = ?
            ORDER BY closed_date ASC
            """,
            (business_id,)
        ).fetchall()

        booking_side_images_left = cursor.execute(
            """
            SELECT *
            FROM booking_side_images
            WHERE business_id = ?
              AND side = 'left'
            ORDER BY sort_order ASC, id ASC
            """,
            (business_id,)
        ).fetchall()

        booking_side_images_right = cursor.execute(
            """
            SELECT *
            FROM booking_side_images
            WHERE business_id = ?
              AND side = 'right'
            ORDER BY sort_order ASC, id ASC
            """,
            (business_id,)
        ).fetchall()

        staff_accounts = cursor.execute(
            """
            SELECT
                u.id,
                u.business_id,
                u.employee_id,
                u.email,
                u.full_name,
                u.role,
                u.is_active,
                u.must_change_password,
                u.can_manage_settings,
                u.can_manage_staff,
                u.can_manage_security,
                u.can_manage_services,
                u.can_manage_bookings,
                u.can_view_clients,
                u.can_edit_clients,
                u.can_view_reports,
                u.last_login_at,
                u.created_at
            FROM users u
            WHERE u.role = 'staff'
              AND u.business_id = ?
            ORDER BY u.id DESC
            """,
            (business_id,)
        ).fetchall()

    finally:
        conn.close()

    employee_ids = [employee["id"] for employee in employees]

    employee_schedule_map = build_employee_schedule_map()
    employee_time_off_map = build_employee_time_off_map(employee_ids)
    employee_schedule_exceptions_map = build_employee_schedule_exceptions_map(employee_ids)

    return render_template(
        "admin_settings.html",
        current_role=current_role,
        settings=settings,
        admin_login_email=current_user["email"] if current_user and current_user["email"] else "",
        employees=employees,
        closed_days=closed_days,
        employee_schedule_map=employee_schedule_map,
        employee_time_off_map=employee_time_off_map,
        employee_schedule_exceptions_map=employee_schedule_exceptions_map,
        booking_side_images_left=booking_side_images_left,
        booking_side_images_right=booking_side_images_right,
        staff_accounts=staff_accounts,
    )


@app.route("/admin/settings/employees/add", methods=["POST"])
@client_admin_required
def add_employee():
    business_id = session.get("business_id", 1)

    full_name = (request.form.get("employee_name") or "").strip()
    role = (request.form.get("employee_role") or "").strip()
    email = (request.form.get("employee_email") or "").strip()

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

    try:
        cursor.execute("""
            INSERT INTO employees (business_id, full_name, role, email, photo_path, active)
            VALUES (?, ?, ?, ?, ?, 1)
        """, (
            business_id,
            full_name,
            role or None,
            email or None,
            photo_path
        ))

        conn.commit()
        flash("Pracownik został dodany.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd add_employee:", e)
        flash("Nie udało się dodać pracownika.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/employees/<int:employee_id>/delete", methods=["POST"])
@client_admin_required
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

        cursor.execute(
            """
            DELETE FROM employees
            WHERE id = ?
            """,
            (employee_id,)
        )
        conn.commit()

        if photo_path:
            if photo_path.startswith("images/") or photo_path.startswith("uploads/"):
                delete_static_file(photo_path)
            else:
                delete_r2_file(photo_path)

        flash("Pracownik został usunięty.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_employee:", e)
        flash("Nie udało się usunąć pracownika.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/employees/update-schedule", methods=["POST"])
@client_admin_required
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
            employee_name = (request.form.get("employee_name") or "").strip()
            employee_email = (request.form.get("employee_email") or "").strip()
            active = 1 if str(request.form.get("active", "1")) == "1" else 0

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

            old_photo_path = employee_row["photo_path"] or None

            cursor.execute(
                """
                UPDATE employees
                SET full_name = ?, email = ?, active = ?
                WHERE id = ?
                """,
                (
                    employee_name,
                    employee_email or None,
                    active,
                    employee_id,
                )
            )

            if cropped_employee_photo_data:
                try:
                    if "," not in cropped_employee_photo_data:
                        raise ValueError("Nieprawidłowe dane obrazu.")

                    header, encoded = cropped_employee_photo_data.split(",", 1)

                    if "image/png" in header:
                        extension = ".png"
                        content_type = "image/png"
                    elif "image/jpeg" in header or "image/jpg" in header:
                        extension = ".jpg"
                        content_type = "image/jpeg"
                    elif "image/webp" in header:
                        extension = ".webp"
                        content_type = "image/webp"
                    else:
                        extension = ".jpg"
                        content_type = "image/jpeg"

                    image_bytes = base64.b64decode(encoded)
                    file_key = f"employees/employee_{employee_id}_{uuid.uuid4().hex}{extension}"

                    new_photo_path = upload_bytes_to_r2(
                        file_bytes=image_bytes,
                        object_key=file_key,
                        content_type=content_type,
                    )

                    cursor.execute(
                        """
                        UPDATE employees
                        SET photo_path = ?
                        WHERE id = ?
                        """,
                        (new_photo_path, employee_id)
                    )

                    if old_photo_path and old_photo_path != new_photo_path:
                        if old_photo_path.startswith("images/") or old_photo_path.startswith("uploads/"):
                            delete_static_file(old_photo_path)
                        else:
                            delete_r2_file(old_photo_path)

                except (ValueError, binascii.Error) as e:
                    print("Błąd zapisu przyciętego zdjęcia:", e)
                    flash("Nie udało się zapisać przyciętego zdjęcia.", "error")
                    return redirect(url_for("admin_settings"))

                except Exception as e:
                    print("Błąd uploadu przyciętego zdjęcia do R2:", e)
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
                    if old_photo_path.startswith("images/") or old_photo_path.startswith("uploads/"):
                        delete_static_file(old_photo_path)
                    else:
                        delete_r2_file(old_photo_path)

            elif photo_file and photo_file.filename:
                original_filename = secure_filename(photo_file.filename)
                _, extension = os.path.splitext(original_filename)
                extension = extension.lower()

                allowed_extensions = {".png", ".jpg", ".jpeg", ".webp"}
                if extension not in allowed_extensions:
                    flash("Dozwolone formaty zdjęcia to: PNG, JPG, JPEG, WEBP.", "error")
                    return redirect(url_for("admin_settings"))

                if extension == ".png":
                    content_type = "image/png"
                elif extension in {".jpg", ".jpeg"}:
                    content_type = "image/jpeg"
                else:
                    content_type = "image/webp"

                file_key = f"employees/employee_{employee_id}_{uuid.uuid4().hex}{extension}"
                photo_bytes = photo_file.read()

                new_photo_path = upload_bytes_to_r2(
                    file_bytes=photo_bytes,
                    object_key=file_key,
                    content_type=content_type,
                )

                cursor.execute(
                    """
                    UPDATE employees
                    SET photo_path = ?
                    WHERE id = ?
                    """,
                    (new_photo_path, employee_id)
                )

                if old_photo_path and old_photo_path != new_photo_path:
                    if old_photo_path.startswith("images/") or old_photo_path.startswith("uploads/"):
                        delete_static_file(old_photo_path)
                    else:
                        delete_r2_file(old_photo_path)

            cursor.execute(
                """
                DELETE FROM employee_work_schedule
                WHERE employee_id = ?
                """,
                (employee_id,)
            )

            for day_key in weekday_keys:
                enabled = 1 if request.form.get(f"{day_key}_enabled") else 0
                start_time = normalize_text_time_value(request.form.get(f"{day_key}_start"))
                end_time = normalize_text_time_value(request.form.get(f"{day_key}_end"))

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
                        enabled,
                        start_time if enabled else None,
                        end_time if enabled else None,
                    )
                )

            conn.commit()
            flash("Zapisano dane pracownika.", "success")

        elif time_off_action == "add_vacation":
            date_from = normalize_text_date_to_db(request.form.get("vacation_date_from"))
            date_to = normalize_text_date_to_db(request.form.get("vacation_date_to"))
            note = (request.form.get("vacation_note") or "").strip()

            if not date_from or not date_to:
                flash("Podaj poprawny zakres dat dla urlopu w formacie DD.MM.YYYY.", "error")
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
            date_from = normalize_text_date_to_db(request.form.get("sick_date_from"))
            date_to = normalize_text_date_to_db(request.form.get("sick_date_to"))
            note = (request.form.get("sick_note") or "").strip()

            if not date_from or not date_to:
                flash("Podaj poprawny zakres dat dla chorobowego w formacie DD.MM.YYYY.", "error")
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
            exception_date = normalize_text_date_to_db(request.form.get("exception_date"))
            exception_type = (request.form.get("exception_type") or "").strip()
            exception_start_time = normalize_text_time_value(request.form.get("exception_start_time"))
            exception_end_time = normalize_text_time_value(request.form.get("exception_end_time"))
            exception_note = (request.form.get("exception_note") or "").strip()

            if not exception_date:
                flash("Podaj poprawną datę wyjątkowego dnia w formacie DD.MM.YYYY.", "error")

            elif exception_type not in ["custom_hours", "day_off"]:
                flash("Nieprawidłowy rodzaj wyjątku.", "error")

            elif exception_type == "custom_hours" and (not exception_start_time or not exception_end_time):
                flash("Podaj poprawne godziny dla niestandardowego dnia pracy w formacie HH:MM.", "error")

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
                        exception_note or None,
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
@client_admin_required
def update_settings():
    business_id = session.get("business_id", 1)

    company_name = (request.form.get("company_name") or "").strip()
    company_address = (request.form.get("company_address") or "").strip()
    contact_phone = (request.form.get("contact_phone") or "").strip()
    contact_email = (request.form.get("contact_email") or "").strip()
    website_url = (request.form.get("website_url") or "").strip()
    privacy_policy_url = (request.form.get("privacy_policy_url") or "").strip()
    terms_url = (request.form.get("terms_url") or "").strip()
    primary_color = (request.form.get("primary_color") or "").strip()

    slot_interval_minutes = request.form.get("slot_interval_minutes", type=int)
    logo_width = request.form.get("logo_width", type=int)
    logo_height = request.form.get("logo_height", type=int)
    company_name_size = request.form.get("company_name_size", type=int)
    logo_text_gap = request.form.get("logo_text_gap", type=int)

    def normalize_url(value):
        value = (value or "").strip()
        if value and not value.startswith(("http://", "https://")):
            return f"https://{value}"
        return value

    website_url = normalize_url(website_url)
    privacy_policy_url = normalize_url(privacy_policy_url)
    terms_url = normalize_url(terms_url)

    if not company_name or not primary_color or not slot_interval_minutes:
        flash("Proszę uzupełnić wszystkie wymagane ustawienia.", "error")
        return redirect(url_for("admin_settings"))

    logo_width = 120 if logo_width is None else max(40, min(260, logo_width))
    logo_height = 44 if logo_height is None else max(20, min(120, logo_height))
    company_name_size = 22 if company_name_size is None else max(12, min(42, company_name_size))
    logo_text_gap = 12 if logo_text_gap is None else max(0, min(40, logo_text_gap))
    slot_interval_minutes = max(5, min(180, slot_interval_minutes))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        ensure_column(cursor, "business_settings", "website_url", "website_url TEXT")
        ensure_column(cursor, "business_settings", "privacy_policy_url", "privacy_policy_url TEXT")
        ensure_column(cursor, "business_settings", "terms_url", "terms_url TEXT")

        cursor.execute(
            "SELECT logo_path FROM business_settings WHERE business_id = ? LIMIT 1",
            (business_id,)
        )
        current_settings = cursor.fetchone()
        current_logo_path = current_settings["logo_path"] if current_settings else None

        logo_path = current_logo_path
        logo_file = request.files.get("logo_file")

        if logo_file and logo_file.filename:
            upload_folder = os.path.join(app.static_folder, "uploads", "logos")
            os.makedirs(upload_folder, exist_ok=True)

            safe_name = secure_filename(logo_file.filename)
            filename = f"company_logo_{business_id}_{safe_name}"
            save_path = os.path.join(upload_folder, filename)

            logo_file.save(save_path)
            logo_path = f"uploads/logos/{filename}"

        cursor.execute(
            """
            INSERT OR IGNORE INTO business_settings (
                business_id,
                company_name,
                company_address,
                contact_phone,
                contact_email,
                website_url,
                privacy_policy_url,
                terms_url,
                primary_color,
                slot_interval_minutes,
                logo_path,
                logo_width,
                logo_height,
                company_name_size,
                logo_text_gap
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
                "Booking System",
                "",
                "",
                "kontakt@example.com",
                "",
                "",
                "",
                "#1f3c88",
                30,
                None,
                120,
                44,
                22,
                12,
            )
        )

        cursor.execute(
            """
            UPDATE business_settings
            SET
                company_name = ?,
                company_address = ?,
                contact_phone = ?,
                contact_email = ?,
                website_url = ?,
                privacy_policy_url = ?,
                terms_url = ?,
                primary_color = ?,
                slot_interval_minutes = ?,
                logo_path = ?,
                logo_width = ?,
                logo_height = ?,
                company_name_size = ?,
                logo_text_gap = ?
            WHERE business_id = ?
            """,
            (
                company_name,
                company_address,
                contact_phone,
                contact_email,
                website_url,
                privacy_policy_url,
                terms_url,
                primary_color,
                slot_interval_minutes,
                logo_path,
                logo_width,
                logo_height,
                company_name_size,
                logo_text_gap,
                business_id,
            )
        )

        conn.commit()

    finally:
        conn.close()

    flash("Ustawienia zostały zapisane.", "success")
    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/delete-logo", methods=["POST"])
@client_admin_required
def delete_logo():
    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT logo_path FROM business_settings WHERE business_id = ? LIMIT 1",
            (business_id,)
        )
        settings = cursor.fetchone()

        if settings and settings["logo_path"]:
            file_path = os.path.join(app.static_folder, settings["logo_path"])

            if os.path.exists(file_path):
                try:
                    os.remove(file_path)
                except Exception:
                    pass

            cursor.execute(
                """
                UPDATE business_settings
                SET logo_path = NULL
                WHERE business_id = ?
                """,
                (business_id,)
            )
            conn.commit()

    finally:
        conn.close()

    flash("Logo zostało usunięte.", "success")
    return redirect(url_for("admin_settings"))


# =========================================================
# CLOSED DAYS
# =========================================================

@app.route("/admin/closed-days/add", methods=["POST"])
@client_admin_required
def add_closed_day():
    business_id = session.get("business_id", 1)
    closed_date = (request.form.get("closed_date") or "").strip()
    note = (request.form.get("note") or "").strip()

    if not closed_date:
        flash("Data wyłączenia jest wymagana.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO closed_days (business_id, closed_date, note)
            VALUES (?, ?, ?)
            """,
            (business_id, closed_date, note or None)
        )
        conn.commit()
        flash("Dzień wyłączony został dodany.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd add_closed_day:", e)
        flash("Taki dzień wyłączony już istnieje lub nie udało się go zapisać.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/closed-days/<int:closed_day_id>/delete", methods=["POST"])
@client_admin_required
def delete_closed_day(closed_day_id):
    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            DELETE FROM closed_days
            WHERE id = ?
              AND business_id = ?
            """,
            (closed_day_id, business_id)
        )
        conn.commit()
        flash("Dzień wyłączony został usunięty.", "success")

    finally:
        conn.close()

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


@app.route("/admin/bookings/<int:booking_id>/archive-status", methods=["POST"])
@admin_required
def update_archived_booking_status(booking_id):
    new_status = (request.form.get("status") or "").strip().lower()

    allowed_statuses = ["completed", "no_show"]

    if new_status not in allowed_statuses:
        flash("Nieprawidłowy status archiwalnej rezerwacji.", "error")
        return redirect(url_for("admin_dashboard"))

    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, status, archived, client_id
            FROM bookings
            WHERE id = ?
            LIMIT 1
        """, (booking_id,))

        booking = cursor.fetchone()

        if not booking:
            flash("Nie znaleziono rezerwacji.", "error")
            return redirect(url_for("admin_dashboard"))

        if int(booking["archived"] or 0) != 1:
            flash("Status można oznaczyć tylko w archiwum.", "error")
            return redirect(url_for("admin_dashboard"))

        if (booking["status"] or "").strip().lower() != "confirmed":
            flash("Ta rezerwacja została już oznaczona.", "info")
            return redirect(url_for("admin_dashboard"))

        cursor.execute("""
            UPDATE bookings
            SET status = ?
            WHERE id = ?
              AND COALESCE(archived, 0) = 1
        """, (new_status, booking_id))

        if new_status == "no_show":
            cursor.execute("""
                UPDATE clients
                SET blacklisted = 1,
                    blacklist_reason = COALESCE(NULLIF(blacklist_reason, ''), 'Nieobecność na wizycie'),
                    blacklisted_at = COALESCE(blacklisted_at, datetime('now'))
                WHERE id = ?
                  AND business_id = ?
            """, (booking["client_id"], business_id))

        conn.commit()

        # Brak flash success — strona tylko odświeża się i wraca do tej samej pozycji.

    except Exception as e:
        conn.rollback()
        print("Błąd update_archived_booking_status:", e)
        flash("Nie udało się zaktualizować statusu rezerwacji.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/bookings/report")
@permission_required("can_view_reports")
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
@client_admin_required
def update_admin_email():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        admin_id = session.get("admin_id")
        new_email = (request.form.get("admin_email") or "").strip().lower()

        if not admin_id:
            flash("Nie udało się ustalić zalogowanego użytkownika.", "error")
            return redirect(url_for("admin_settings"))

        if not new_email:
            flash("Podaj adres e-mail logowania.", "error")
            return redirect(url_for("admin_settings"))

        existing_user = cursor.execute("""
            SELECT id
            FROM users
            WHERE lower(email) = lower(?)
              AND id != ?
            LIMIT 1
        """, (new_email, admin_id)).fetchone()

        if existing_user:
            flash("Ten adres e-mail jest już zajęty.", "error")
            return redirect(url_for("admin_settings"))

        cursor.execute("""
            UPDATE users
            SET email = ?
            WHERE id = ?
        """, (new_email, admin_id))

        conn.commit()

        session["admin_email"] = new_email

        flash("Adres e-mail logowania został zaktualizowany.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd update_admin_email:", e)
        flash("Nie udało się zaktualizować adresu e-mail logowania.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))





@app.route("/admin/waitlist/<int:waitlist_entry_id>/book", methods=["POST"])
@admin_required
def create_booking_from_waitlist(waitlist_entry_id):
    business_id = session.get("business_id", 1)

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
            clear_waitlist_match(waitlist_entry_id)
            flash("Ten termin nie jest już dostępny. Wpis wrócił do oczekujących.", "error")
            return redirect(url_for("admin_dashboard"))

        client_id = waitlist_row["client_id"] if "client_id" in waitlist_row.keys() else None

        if not client_id:
            client_id = get_or_create_client(
                business_id=business_id,
                full_name=waitlist_row["client_name"] or "",
                phone=waitlist_row["client_phone"] or "",
                email=waitlist_row["client_email"] or "",
                privacy_consent=0,
                marketing_consent=0,
                consent_source="waitlist_dashboard_promote"
            )

        if not client_id:
            flash("Nie udało się utworzyć lub odnaleźć karty klienta.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            INSERT INTO bookings (
                business_id,
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
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
                service_id,
                employee_id,
                client_id,
                waitlist_row["client_name"],
                waitlist_row["client_email"] or None,
                waitlist_row["client_phone"] or None,
                booking_date,
                booking_time,
                waitlist_row["notes"] or None,
                "confirmed"
            )
        )

        new_booking_id = cursor.lastrowid

        cursor.execute(
            """
            UPDATE waitlist_entries
            SET status = 'booked'
            WHERE id = ?
            """,
            (waitlist_entry_id,)
        )

        conn.commit()

        try:
            booking_data = fetch_booking_notification_data(new_booking_id)
            if booking_data:
                notification_ctx = get_booking_notification_context(booking_data)
                send_waitlist_promoted_emails(notification_ctx)
        except Exception as mail_error:
            print("Błąd wysyłki maili po przeniesieniu z waitlisty:", mail_error)

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

    privacy_consent = 1 if request.form.get("privacy_consent") else 0
    marketing_consent = 1 if request.form.get("marketing_consent") == "1" else 0
    consents_created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cancel_token = secrets.token_urlsafe(32)

    if not service_id or not employee_id or not client_name:
        flash("Uzupełnij wymagane dane listy oczekujących.", "error")
        return redirect(url_for("booking"))


    if not privacy_consent:
        flash(
            "Aby zapisać się na listę oczekujących, należy potwierdzić zapoznanie się z polityką prywatności.",
            "error"
        )
        return redirect(url_for("booking"))

    if TURNSTILE_ENABLED:
        turnstile_token = (request.form.get("cf-turnstile-response") or "").strip()
        if not verify_turnstile_token(turnstile_token, request.remote_addr):
            flash("Weryfikacja bezpieczeństwa nie powiodła się. Spróbuj ponownie.", "error")
            return redirect(url_for("booking"))

    if preferred_date_from and has_matching_available_slot(
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

    settings = get_settings()
    business_id = (
        settings["business_id"]
        if settings and "business_id" in settings.keys() and settings["business_id"]
        else 1
    )

    client_id = get_or_create_client(
        business_id=business_id,
        full_name=client_name,
        phone=client_phone,
        email=client_email,
        privacy_consent=privacy_consent,
        marketing_consent=marketing_consent,
        consent_source="waitlist_form",
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
            SELECT name
            FROM services
            WHERE id = ?
            LIMIT 1
            """,
            (service_id,)
        )
        service_row = cursor.fetchone()

        cursor.execute(
            """
            SELECT full_name
            FROM employees
            WHERE id = ?
            LIMIT 1
            """,
            (employee_id,)
        )
        employee_row = cursor.fetchone()

        cursor.execute(
            """
            INSERT INTO waitlist_entries (
                business_id,
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email,
                client_phone,
                preferred_date_from,
                preferred_date_to,
                preferred_time_from,
                preferred_time_to,
                notes,
                status,
                privacy_consent,
                marketing_consent,
                consents_created_at,
                cancel_token,
                cancel_token_used
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email or None,
                client_phone or None,
                preferred_date_from or None,
                preferred_date_to or None,
                preferred_time_from or None,
                preferred_time_to or None,
                notes or None,
                "waiting",
                privacy_consent,
                marketing_consent,
                consents_created_at,
                cancel_token,
                0
            )
        )

        waitlist_entry_id = cursor.lastrowid
        conn.commit()

        try:
            send_waitlist_internal_notifications(waitlist_entry_id)
        except Exception as e:
            print("Błąd wysyłki maili wewnętrznych dla waitlisty:", e)

        if client_email:
            try:
                send_waitlist_verification_email(waitlist_entry_id)
            except Exception as e:
                print("Błąd wysyłki maila weryfikacyjnego dla waitlisty:", e)

        session["waitlist_thank_you_data"] = {
            "client_name": client_name,
            "client_email": client_email,
            "client_phone": client_phone,
            "service_name": service_row["name"] if service_row else "",
            "employee_name": employee_row["full_name"] if employee_row else "",
            "preferred_date_from": preferred_date_from,
            "preferred_date_to": preferred_date_to,
            "preferred_time_from": preferred_time_from,
            "preferred_time_to": preferred_time_to,
            "notes": notes,
        }

    except Exception as e:
        conn.rollback()
        print("Błąd create_waitlist_entry:", e)
        flash("Nie udało się zapisać zgłoszenia do listy oczekujących.", "error")
        return redirect(url_for("booking"))

    finally:
        conn.close()

    return redirect(url_for("waitlist_thank_you"))


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


@app.route("/admin/waitlist/<int:waitlist_entry_id>/update", methods=["POST"])
@admin_required
def update_waitlist_entry(waitlist_entry_id):
    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()
    preferred_date_from = (request.form.get("preferred_date_from") or "").strip()
    preferred_date_to = (request.form.get("preferred_date_to") or "").strip()
    preferred_time_from = (request.form.get("preferred_time_from") or "").strip()
    preferred_time_to = (request.form.get("preferred_time_to") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if not client_name:
        flash("Podaj imię i nazwisko klienta.", "error")
        return redirect(url_for("admin_dashboard"))

    if not client_phone:
        flash("Podaj numer telefonu klienta.", "error")
        return redirect(url_for("admin_dashboard"))

    if preferred_date_from and preferred_date_to and preferred_date_from > preferred_date_to:
        flash("Zakres dat jest nieprawidłowy.", "error")
        return redirect(url_for("admin_dashboard"))

    if preferred_time_from and preferred_time_to and preferred_time_from > preferred_time_to:
        flash("Zakres godzin jest nieprawidłowy.", "error")
        return redirect(url_for("admin_dashboard"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM waitlist_entries
            WHERE id = ?
            LIMIT 1
            """,
            (waitlist_entry_id,)
        )
        row = cursor.fetchone()

        if not row:
            flash("Nie znaleziono wpisu na liście oczekujących.", "error")
            return redirect(url_for("admin_dashboard"))

        cursor.execute(
            """
            UPDATE waitlist_entries
            SET
                client_name = ?,
                client_email = ?,
                client_phone = ?,
                preferred_date_from = ?,
                preferred_date_to = ?,
                preferred_time_from = ?,
                preferred_time_to = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                client_name,
                client_email or None,
                client_phone or None,
                preferred_date_from or None,
                preferred_date_to or None,
                preferred_time_from or None,
                preferred_time_to or None,
                notes or None,
                waitlist_entry_id
            )
        )

        conn.commit()
        flash("Wpis z listy oczekujących został zaktualizowany.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd update_waitlist_entry:", e)
        flash("Nie udało się zaktualizować wpisu listy oczekujących.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_dashboard"))



@app.route("/admin/bookings/<int:booking_id>/update", methods=["POST"])
@admin_required
def update_booking(booking_id):
    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()
    status = (request.form.get("status") or "").strip().lower()
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
            SELECT
                client_id,
                service_id,
                employee_id,
                booking_date,
                booking_time,
                status
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

    if status in ("confirmed", "cancelled") and previous_status != status:
        try:
            booking_data = fetch_booking_notification_data(booking_id)
            if booking_data:
                notification_ctx = get_booking_notification_context(booking_data)
                send_booking_status_changed_emails(notification_ctx, status)
        except Exception as mail_error:
            print("Błąd wysyłki maili po edycji rezerwacji:", mail_error)

    flash("Rezerwacja została zaktualizowana.", "success")
    return redirect(url_for("admin_dashboard"))



@app.route("/admin/clients")
@admin_required
def admin_clients():
    can_view_clients = current_user_can_view_clients()
    can_edit_clients = current_user_can_edit_clients()

    if not can_view_clients:
        flash("To konto nie ma dostępu do sekcji klientów.", "error")
        return redirect(url_for("admin_dashboard"))

    business_id = session.get("business_id", 1)
    ensure_clients_blacklist_columns()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        settings = get_settings()
        is_staff = current_user_is_staff()
        clients_read_only = can_view_clients and not can_edit_clients

        # 🔽 POBIERANIE KLIENTÓW
        cursor.execute("""
            SELECT
                c.id,
                c.full_name,
                c.phone,
                c.email,
                c.notes,
                c.created_at,
                c.updated_at,
                c.preferred_employee_id,
                COALESCE(c.blacklisted, 0) AS blacklisted,
                c.blacklist_reason,
                c.blacklisted_at,

                -- 🔥 odbyte wizyty (completed)
                COUNT(
                    CASE
                        WHEN b.booking_date < date('now')
                         AND LOWER(COALESCE(b.status, '')) = 'completed'
                        THEN 1
                    END
                ) AS completed_visits,

                -- 🔥 ostatnia odbyta wizyta
                MAX(
                    CASE
                        WHEN b.booking_date < date('now')
                         AND LOWER(COALESCE(b.status, '')) = 'completed'
                        THEN b.booking_date || ' ' || COALESCE(b.booking_time, '00:00')
                    END
                ) AS last_completed_visit_at,

                -- 🔥 najbliższa przyszła wizyta
                MIN(
                    CASE
                        WHEN b.booking_date >= date('now')
                         AND LOWER(COALESCE(b.status, '')) IN ('new', 'confirmed')
                         AND COALESCE(b.archived, 0) = 0
                        THEN b.booking_date || ' ' || COALESCE(b.booking_time, '00:00')
                    END
                ) AS next_booking_at

            FROM clients c
            LEFT JOIN bookings b
                ON b.client_id = c.id
               AND b.business_id = c.business_id

            WHERE c.business_id = ?

            GROUP BY
                c.id,
                c.full_name,
                c.phone,
                c.email,
                c.notes,
                c.created_at,
                c.updated_at,
                c.preferred_employee_id

            ORDER BY c.id DESC
        """, (business_id,))

        client_rows = cursor.fetchall()

        # 🔥 STATUSY KLIENTÓW
        clients = []
        for row in client_rows:
            client = dict(row)

            client["client_status"] = calculate_client_status(
                client["completed_visits"],
                client["last_completed_visit_at"],
                client["next_booking_at"]
            )

            clients.append(client)

        # 🔽 PRACOWNICY
        cursor.execute("""
            SELECT
                id,
                full_name
            FROM employees
            WHERE business_id = ?
              AND active = 1
            ORDER BY full_name ASC
        """, (business_id,))

        employee_rows = cursor.fetchall()

        employees = [
            {
                "id": row["id"],
                "full_name": row["full_name"]
            }
            for row in employee_rows
        ]

    finally:
        conn.close()

    return render_template(
        "admin_clients.html",
        page_title="Klienci",
        settings=settings,
        clients=clients,
        employees=employees,
        is_staff=is_staff,
        clients_read_only=clients_read_only
    )


@app.route("/admin/clients/<int:client_id>/update", methods=["POST"])
@admin_required
def update_client(client_id):
    if not current_user_can_edit_clients():
        flash("To konto nie ma uprawnień do edycji klientów.", "error")
        return redirect(url_for("admin_clients"))

    full_name = (request.form.get("full_name") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    email = (request.form.get("email") or "").strip()
    notes = (request.form.get("notes") or "").strip()
    preferred_employee_id_raw = (request.form.get("preferred_employee_id") or "").strip()

    if current_user_is_staff():
        privacy_consent = None
        marketing_consent = None
    else:
        privacy_consent = 1 if request.form.get("privacy_consent") == "1" else 0
        marketing_consent = 1 if request.form.get("marketing_consent") == "1" else 0

    if not full_name:
        flash("Podaj imię i nazwisko klienta.", "error")
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

        if current_user_is_staff():
            staff_employee_id = current_staff_employee_id()

            cursor.execute(
                """
                SELECT 1
                FROM bookings
                WHERE client_id = ?
                  AND employee_id = ?
                LIMIT 1
                """,
                (client_id, staff_employee_id)
            )
            allowed_row = cursor.fetchone()

            if not allowed_row:
                flash("Brak dostępu do edycji tego klienta.", "error")
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

        if current_user_is_staff():
            cursor.execute(
                """
                UPDATE clients
                SET
                    full_name = ?,
                    phone = ?,
                    email = ?,
                    notes = ?,
                    preferred_employee_id = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    full_name,
                    phone or None,
                    email or None,
                    notes or None,
                    preferred_employee_id,
                    updated_at,
                    client_id
                )
            )
        else:
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


@app.route("/admin/clients/<int:client_id>/details")
@admin_required
def client_details(client_id):
    if not current_user_can_view_clients():
        return jsonify({"error": "Brak dostępu."}), 403

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

        if current_user_is_staff():
            staff_employee_id = current_staff_employee_id()

            cursor.execute(
                """
                SELECT 1
                FROM bookings
                WHERE client_id = ?
                  AND employee_id = ?
                LIMIT 1
                """,
                (client_id, staff_employee_id)
            )
            allowed_row = cursor.fetchone()

            if not allowed_row:
                return jsonify({"error": "Brak dostępu do tego klienta."}), 403

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
            "active_bookings": [
                {
                    "id": row["id"],
                    "booking_date": row["booking_date"],
                    "booking_time": row["booking_time"],
                    "status": get_booking_status_label(row["status"]),
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
                    "status": get_booking_status_label(row["status"]),
                    "notes": row["notes"],
                    "archived": row["archived"],
                    "service_name": row["service_name"],
                    "employee_name": row["employee_name"],
                }
                for row in history_rows
            ],
        }

        if not current_user_is_staff():
            response["consents"] = {
                "privacy_consent": client["privacy_consent"],
                "marketing_consent": client["marketing_consent"],
                "privacy_consent_at": client["privacy_consent_at"],
                "marketing_consent_at": client["marketing_consent_at"],
                "consent_source": client["consent_source"],
                "privacy_notice_confirmed": client["privacy_notice_confirmed"],
                "privacy_notice_confirmed_at": client["privacy_notice_confirmed_at"],
                "privacy_notice_source": client["privacy_notice_source"],
            }

        return jsonify(response)

    except Exception as e:
        print("Błąd client_details:", e)
        return jsonify({"error": "Nie udało się pobrać szczegółów klienta."}), 500

    finally:
        conn.close()


@app.route("/admin/clients/<int:client_id>/send-consent-link", methods=["POST"])
@admin_required
def send_client_consent_link(client_id):
    if not current_user_can_edit_clients():
        return jsonify({
            "success": False,
            "message": "Brak uprawnień do wysyłki linku zgód."
        }), 403

    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        client = cursor.execute("""
            SELECT *
            FROM clients
            WHERE id = ?
              AND business_id = ?
            LIMIT 1
        """, (client_id, business_id)).fetchone()

        if not client:
            return jsonify({
                "success": False,
                "message": "Nie znaleziono klienta."
            }), 404

        client_email = (client["email"] or "").strip()

        if not client_email:
            return jsonify({
                "success": False,
                "message": "Klient nie ma adresu e-mail."
            }), 400

        settings = get_settings(business_id)

    finally:
        conn.close()

    token = assign_client_verification_token(client_id)

    if not token:
        return jsonify({
            "success": False,
            "message": "Nie udało się wygenerować linku zgód."
        }), 500

    consents_link = url_for("client_consents", token=token, _external=True)

    company_name = settings["company_name"] if settings and settings["company_name"] else "Salon"

    subject = "Ustawienia zgód i polityka prywatności"

    html_body = render_template(
        "emails/client_consent_request.html",
        client=client,
        settings=settings,
        consents_link=consents_link,
        email_title=subject,
        email_heading="Ustawienia zgód klienta",
        company_name=company_name,
        company_address=settings["company_address"] if settings else "",
        contact_phone=settings["contact_phone"] if settings else "",
        contact_email=settings["contact_email"] if settings else "",
        website_url=settings["website_url"] if settings else "",
    )

    text_body = (
        f"Dzień dobry {client['full_name'] or ''},\n\n"
        f"{company_name} prosi o potwierdzenie ustawień zgód klienta.\n\n"
        "Kliknij poniższy link, aby przejść do centrum zgód:\n\n"
        f"{consents_link}\n\n"
        "Na stronie możesz potwierdzić zapoznanie się z polityką prywatności "
        "oraz zdecydować, czy chcesz otrzymywać informacje marketingowe.\n\n"
        f"Pozdrawiamy,\n{company_name}"
    )

    try:
        send_email_message(client_email, subject, html_body, text_body)

    except Exception as e:
        print("Błąd wysyłki linku zgód:", e)
        return jsonify({
            "success": False,
            "message": "Nie udało się wysłać wiadomości e-mail."
        }), 500

    return jsonify({
        "success": True,
        "message": "Link do ustawień zgód został wysłany do klienta."
    })




@app.route("/admin/settings/booking-media/update", methods=["POST"])
@client_admin_required
def update_booking_media_settings():
    business_id = session.get("business_id", 1)

    side_panels_enabled = 1 if request.form.get("side_panels_enabled") == "1" else 0
    side_panels_autoplay = 1 if request.form.get("side_panels_autoplay") == "1" else 0
    side_panels_interval = request.form.get("side_panels_interval", type=int)

    if side_panels_interval is None:
        side_panels_interval = 6

    side_panels_interval = max(3, min(20, side_panels_interval))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT OR IGNORE INTO business_settings (
                business_id,
                company_name,
                company_address,
                contact_phone,
                contact_email,
                primary_color,
                slot_interval_minutes,
                side_panels_enabled,
                side_panels_autoplay,
                side_panels_interval,
                logo_width,
                logo_height,
                company_name_size,
                logo_text_gap
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
                "Booking System",
                "",
                "",
                "kontakt@example.com",
                "#1f3c88",
                30,
                side_panels_enabled,
                side_panels_autoplay,
                side_panels_interval,
                120,
                44,
                22,
                12,
            )
        )

        cursor.execute(
            """
            UPDATE business_settings
            SET
                side_panels_enabled = ?,
                side_panels_autoplay = ?,
                side_panels_interval = ?
            WHERE business_id = ?
            """,
            (
                side_panels_enabled,
                side_panels_autoplay,
                side_panels_interval,
                business_id,
            )
        )

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
@client_admin_required
def add_booking_side_image():
    business_id = session.get("business_id", 1)

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

    filename = f"booking_side_{business_id}_{side}_{uuid.uuid4().hex}{extension}"
    object_key = f"booking-side-images/{filename}"

    conn = None

    try:
        image_key = upload_fileobj_to_r2(
            fileobj=image,
            object_key=object_key,
            content_type=image.mimetype or None,
        )

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COALESCE(MAX(sort_order), 0) + 1 AS next_order
            FROM booking_side_images
            WHERE business_id = ?
              AND side = ?
            """,
            (business_id, side)
        )
        row = cursor.fetchone()
        next_order = row["next_order"] if row and row["next_order"] else 1

        cursor.execute(
            """
            INSERT INTO booking_side_images (
                business_id,
                side,
                image_path,
                sort_order,
                is_active
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (business_id, side, image_key, next_order)
        )

        conn.commit()
        flash("Zdjęcie boczne zostało dodane.", "success")

    except Exception as e:
        if conn:
            conn.rollback()
        print("Błąd add_booking_side_image:", e)
        flash("Nie udało się dodać zdjęcia bocznego.", "error")

    finally:
        if conn:
            conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/<int:image_id>/delete", methods=["POST"])
@client_admin_required
def delete_booking_side_image(image_id):
    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, side, sort_order, image_path
            FROM booking_side_images
            WHERE id = ?
              AND business_id = ?
            LIMIT 1
            """,
            (image_id, business_id)
        )
        image_row = cursor.fetchone()

        if not image_row:
            flash("Nie znaleziono zdjęcia.", "error")
            return redirect(url_for("admin_settings"))

        image_path = image_row["image_path"]
        deleted_side = image_row["side"]
        deleted_sort_order = image_row["sort_order"]

        cursor.execute(
            """
            DELETE FROM booking_side_images
            WHERE id = ?
              AND business_id = ?
            """,
            (image_id, business_id)
        )

        cursor.execute(
            """
            UPDATE booking_side_images
            SET sort_order = sort_order - 1
            WHERE business_id = ?
              AND side = ?
              AND sort_order > ?
            """,
            (business_id, deleted_side, deleted_sort_order)
        )

        conn.commit()

        delete_r2_file(image_path)
        flash("Zdjęcie boczne zostało usunięte.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_booking_side_image:", e)
        flash("Nie udało się usunąć zdjęcia bocznego.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/admin/settings/booking-side-images/<int:image_id>/move-up", methods=["POST"])
@client_admin_required
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
@client_admin_required
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


@app.route("/admin/generate-activation-link", methods=["GET", "POST"])
@admin_required
def generate_activation_link():
    settings = get_settings()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        business_name = (request.form.get("business_name") or "").strip()

        if not email or not business_name:
            flash("Podaj adres e-mail i nazwę firmy.", "error")
            return render_template(
                "generate_activation_link.html",
                page_title="Generowanie linku aktywacyjnego",
                settings=settings
            )

        if get_user_by_email(email):
            flash("Użytkownik z tym adresem e-mail już istnieje.", "error")
            return render_template(
                "generate_activation_link.html",
                page_title="Generowanie linku aktywacyjnego",
                settings=settings
            )

        base_slug = slugify_business_name(business_name)
        business_slug = ensure_unique_business_slug(base_slug)

        raw_token = create_account_activation_invite(
            email=email,
            business_name=business_name,
            business_slug=business_slug,
            role="client_admin",
            created_by_user_id=None
        )

        activation_link = build_activation_link(request.host_url.rstrip("/"), raw_token)

        print("=" * 80)
        print("LINK AKTYWACYJNY DLA NOWEGO KLIENTA:")
        print(activation_link)
        print("=" * 80)

        flash("Link aktywacyjny został wygenerowany. Sprawdź terminal serwera.", "success")

        return render_template(
            "generate_activation_link.html",
            page_title="Generowanie linku aktywacyjnego",
            settings=settings,
            generated_link=activation_link
        )

    return render_template(
        "generate_activation_link.html",
        page_title="Generowanie linku aktywacyjnego",
        settings=settings
    )


@app.route("/activate-account/<token>", methods=["GET", "POST"])
def activate_account(token):
    settings = get_settings()
    invite = get_valid_account_activation_invite(token)

    if not invite:
        flash("Link aktywacyjny jest nieprawidłowy lub wygasł.", "error")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not full_name or not password or not confirm_password:
            flash("Wypełnij wszystkie pola.", "error")
            return render_template(
                "activate_account.html",
                page_title="Aktywacja konta",
                settings=settings,
                invite=invite
            )

        if password != confirm_password:
            flash("Hasła nie są takie same.", "error")
            return render_template(
                "activate_account.html",
                page_title="Aktywacja konta",
                settings=settings,
                invite=invite
            )

        if len(password) < 8:
            flash("Hasło musi mieć co najmniej 8 znaków.", "error")
            return render_template(
                "activate_account.html",
                page_title="Aktywacja konta",
                settings=settings,
                invite=invite
            )

        conn = get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                SELECT id
                FROM businesses
                WHERE slug = ?
                LIMIT 1
                """,
                (invite["business_slug"],)
            )
            existing_business = cursor.fetchone()

            if existing_business:
                flash("Firma z takim identyfikatorem już istnieje.", "error")
                return render_template(
                    "activate_account.html",
                    page_title="Aktywacja konta",
                    settings=settings,
                    invite=invite
                )

            cursor.execute(
                """
                INSERT INTO businesses (name, slug, owner_email, is_active)
                VALUES (?, ?, ?, 1)
                """,
                (
                    invite["business_name"],
                    invite["business_slug"],
                    invite["email"]
                )
            )
            business_id = cursor.lastrowid

            conn.commit()

        except Exception as e:
            conn.rollback()
            print("Błąd tworzenia business przy aktywacji:", e)
            flash("Nie udało się utworzyć konta firmy.", "error")
            return render_template(
                "activate_account.html",
                page_title="Aktywacja konta",
                settings=settings,
                invite=invite
            )

        finally:
            conn.close()

        created_user_id = create_client_admin(
            business_id=business_id,
            email=invite["email"],
            password=password,
            full_name=full_name
        )

        if not created_user_id:
            flash("Nie udało się utworzyć konta administratora klienta.", "error")
            return render_template(
                "activate_account.html",
                page_title="Aktywacja konta",
                settings=settings,
                invite=invite
            )

        mark_account_activation_invite_as_used(invite["id"])

        flash("Konto zostało aktywowane. Możesz się zalogować.", "success")
        return redirect(url_for("admin_login"))

    return render_template(
        "activate_account.html",
        page_title="Aktywacja konta",
        settings=settings,
        invite=invite
    )


@app.route("/admin/settings/staff-accounts/create", methods=["POST"])
@client_admin_required
def create_staff_account():
    business_id = session.get("business_id", 1)

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    is_active = 1 if request.form.get("is_active") == "1" else 0
    must_change_password = 0

    if not email:
        flash("Podaj adres e-mail konta personelu.", "error")
        return redirect(url_for("admin_settings"))

    if not password or len(password) < 8:
        flash("Hasło musi mieć co najmniej 8 znaków.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        existing_staff = cursor.execute(
            """
            SELECT id
            FROM users
            WHERE business_id = ?
              AND role = 'staff'
            LIMIT 1
            """,
            (business_id,)
        ).fetchone()

        if existing_staff:
            flash("Dla tej firmy istnieje już konto personelu.", "error")
            return redirect(url_for("admin_settings"))

        existing_email = cursor.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email) = LOWER(?)
              AND business_id = ?
            LIMIT 1
            """,
            (email, business_id)
        ).fetchone()

        if existing_email:
            flash("Podany adres e-mail jest już zajęty.", "error")
            return redirect(url_for("admin_settings"))

        user_id = create_staff_user(
            business_id=business_id,
            employee_id=None,
            email=email,
            password=password,
            full_name="Personel",
            must_change_password=must_change_password,
        )

        if not user_id:
            flash("Nie udało się utworzyć konta personelu.", "error")
            return redirect(url_for("admin_settings"))

        cursor.execute(
            """
            UPDATE users
            SET
                is_active = ?,
                can_manage_bookings = 1,
                can_view_clients = 1,
                can_edit_clients = 0,
                can_view_reports = 0,
                can_manage_services = 0,
                can_manage_settings = 0,
                can_manage_staff = 0,
                can_manage_security = 0,
                must_change_password = ?
            WHERE id = ?
              AND business_id = ?
            """,
            (
                is_active,
                must_change_password,
                user_id,
                business_id
            )
        )

        conn.commit()
        flash("Konto personelu zostało utworzone.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd create_staff_account:", e)
        flash("Nie udało się utworzyć konta personelu.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))



@app.route("/admin/settings/staff-accounts/<int:user_id>/toggle-active", methods=["POST"])
@client_admin_required
def toggle_staff_account_active(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, role, is_active
            FROM users
            WHERE id = ?
            LIMIT 1
        """, (user_id,))
        user = cursor.fetchone()

        if not user or user["role"] != "staff":
            flash("Nie znaleziono konta pracownika.", "error")
            return redirect(url_for("admin_settings"))

        new_status = 0 if int(user["is_active"]) == 1 else 1

        cursor.execute("""
            UPDATE users
            SET is_active = ?
            WHERE id = ?
        """, (new_status, user_id))

        conn.commit()
        flash("Status konta pracownika został zaktualizowany.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd toggle_staff_account_active:", e)
        flash("Nie udało się zmienić statusu konta.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))

@app.route("/admin/settings/staff-accounts/<int:user_id>/reset-password", methods=["POST"])
@client_admin_required
def reset_staff_account_password(user_id):
    new_password = request.form.get("new_password") or ""

    if not new_password or len(new_password) < 8:
        flash("Nowe hasło musi mieć co najmniej 8 znaków.", "error")
        return redirect(url_for("admin_settings"))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT id, role
            FROM users
            WHERE id = ?
            LIMIT 1
            """,
            (user_id,)
        )
        user = cursor.fetchone()

        if not user or user["role"] != "staff":
            flash("Nie znaleziono konta personelu.", "error")
            return redirect(url_for("admin_settings"))

        update_user_password(user_id, new_password, must_change_password=0)

        conn.commit()
        flash("Hasło zostało zmienione.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd reset_staff_account_password:", e)
        flash("Nie udało się zmienić hasła.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))



@app.route("/admin/settings/staff-accounts/<int:user_id>/delete", methods=["POST"])
@client_admin_required
def delete_staff_account(user_id):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, role
            FROM users
            WHERE id = ?
            LIMIT 1
        """, (user_id,))
        user = cursor.fetchone()

        if not user or user["role"] != "staff":
            flash("Nie znaleziono konta pracownika.", "error")
            return redirect(url_for("admin_settings"))

        cursor.execute("""
            DELETE FROM users
            WHERE id = ?
        """, (user_id,))

        conn.commit()
        flash("Konto pracownika zostało usunięte.", "success")

    except Exception as e:
        conn.rollback()
        print("Błąd delete_staff_account:", e)
        flash("Nie udało się usunąć konta pracownika.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_settings"))


@app.route("/verify-client-email/<token>")
def verify_client_email(token):
    token = (token or "").strip()

    if not token:
        return render_template("verification/verification_invalid.html")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        client_row = cursor.execute("""
            SELECT
                id,
                email,
                email_verified,
                email_verification_token
            FROM clients
            WHERE email_verification_token = ?
            LIMIT 1
        """, (token,)).fetchone()

        if not client_row:
            return render_template("verification/verification_invalid.html")

        verified_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            UPDATE clients
            SET
                email_verified = 1,
                email_verified_at = ?,
                email_verification_token = NULL,
                email_notifications_enabled = 1,
                email_notifications_disabled_at = NULL,
                privacy_notice_confirmed = 1,
                privacy_notice_confirmed_at = ?,
                privacy_notice_source = ?
            WHERE id = ?
        """, (
            verified_at,
            verified_at,
            "email_verification",
            client_row["id"]
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd verify_client_email:", e)
        return render_template("verification/verification_invalid.html")

    finally:
        conn.close()

    try:
        send_pending_status_emails_after_client_verification(client_row["id"])
    except Exception as e:
        print("Błąd wysyłki zaległych maili statusowych po weryfikacji:", e)

    return render_template("verification/booking_verified_success.html")


# =========================================================
# RUN
# =========================================================

@app.route("/admin/api/dashboard-notifications")
@admin_required
def admin_dashboard_notifications():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                id,
                client_name,
                booking_date,
                booking_time,
                created_at
            FROM bookings
            WHERE COALESCE(archived, 0) = 0
            ORDER BY id DESC
            LIMIT 1
        """)
        latest_booking = cursor.fetchone()

        cursor.execute("""
            SELECT
                id,
                client_name,
                created_at
            FROM waitlist_entries
            WHERE status IN ('waiting', 'matched')
            ORDER BY id DESC
            LIMIT 1
        """)
        latest_waitlist = cursor.fetchone()

        return jsonify({
            "success": True,
            "latest_booking": {
                "id": latest_booking["id"],
                "client_name": latest_booking["client_name"] or "",
                "booking_date": latest_booking["booking_date"] or "",
                "booking_time": latest_booking["booking_time"] or "",
                "created_at": latest_booking["created_at"] or "",
            } if latest_booking else None,
            "latest_waitlist": {
                "id": latest_waitlist["id"],
                "client_name": latest_waitlist["client_name"] or "",
                "created_at": latest_waitlist["created_at"] or "",
            } if latest_waitlist else None,
        })

    except Exception as e:
        print("Błąd admin_dashboard_notifications:", e)
        return jsonify({
            "success": False,
            "latest_booking": None,
            "latest_waitlist": None,
        }), 500

    finally:
        conn.close()



@app.route("/cancel-booking/<token>", methods=["GET"])
def cancel_booking_from_link(token):
    token = (token or "").strip()

    if not token:
        return render_template("emails/booking_cancel_invalid.html"), 400

    token_row = get_booking_cancel_token_record(token)
    is_valid, reason = is_booking_cancel_token_valid(token_row)

    if not is_valid:
        if reason in {"used", "already_cancelled"}:
            return render_template(
                "emails/booking_cancel_invalid.html",
                reason="already_cancelled"
            ), 400

        return render_template(
            "emails/booking_cancel_invalid.html",
            reason=reason
        ), 400

    booking_id = token_row["booking_id"]

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT
                b.id,
                b.business_id,
                b.client_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.status,
                b.service_id,
                b.employee_id,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM bookings b
            LEFT JOIN services s
                ON s.id = b.service_id
            LEFT JOIN employees e
                ON e.id = b.employee_id
            LEFT JOIN business_settings bs
                ON bs.business_id = b.business_id
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        )
        booking_row = cursor.fetchone()

        if not booking_row:
            return render_template("emails/booking_cancel_invalid.html"), 404

        if (booking_row["status"] or "").strip().lower() == "cancelled":
            mark_booking_cancel_token_used(token)
            return render_template(
                "emails/booking_cancel_invalid.html",
                reason="already_cancelled"
            ), 400

        cursor.execute(
            """
            UPDATE bookings
            SET status = ?
            WHERE id = ?
            """,
            ("cancelled", booking_id)
        )

        conn.commit()

        try:
            mark_booking_cancel_token_used(token)
        except Exception as e:
            print("Błąd mark_booking_cancel_token_used:", e)

        try:
            mark_first_waitlist_match_for_slot(
                booking_row["service_id"],
                booking_row["employee_id"],
                booking_row["booking_date"],
                booking_row["booking_time"]
            )
        except Exception as e:
            print("Błąd mark_first_waitlist_match_for_slot po anulowaniu:", e)

        booking_payload = {
            "booking_id": booking_row["id"],
            "business_id": booking_row["business_id"],
            "client_id": booking_row["client_id"],
            "client_name": booking_row["client_name"] or "",
            "client_email": booking_row["client_email"] or "",
            "client_phone": booking_row["client_phone"] or "",
            "booking_date": booking_row["booking_date"] or "",
            "booking_time": booking_row["booking_time"] or "",
            "service_id": booking_row["service_id"],
            "employee_id": booking_row["employee_id"],
            "service_name": booking_row["service_name"] or "",
            "employee_name": booking_row["employee_name"] or "",
            "employee_email": booking_row["employee_email"] or "",
            "company_name": booking_row["company_name"] or "Booking System",
            "contact_email": booking_row["contact_email"] or "",
            "contact_phone": booking_row["contact_phone"] or "",
        }

    except Exception as e:
        conn.rollback()
        print("Błąd cancel_booking_from_link:", e)
        return render_template("emails/booking_cancel_invalid.html"), 500

    finally:
        conn.close()

    try:
        send_booking_cancellation_internal_notifications(booking_payload)
    except Exception as e:
        print("Błąd wysyłki maili wewnętrznych po anulowaniu:", e)

    if (booking_payload["client_email"] or "").strip():
        try:
            send_booking_cancellation_confirmation_email(booking_payload)
        except Exception as e:
            print("Błąd wysyłki maila potwierdzającego anulowanie:", e)

    return render_template(
        "emails/booking_cancel_success.html",
        data=booking_payload
    )


@app.route("/tasks/send-booking-reminders", methods=["POST", "GET"])
def run_day_before_booking_reminders():
    expected_token = app.config.get("INTERNAL_TASK_TOKEN", "").strip()
    provided_token = (
        request.headers.get("X-Task-Token", "").strip()
        or request.args.get("token", "").strip()
    )

    if not expected_token or provided_token != expected_token:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    result = send_day_before_booking_reminders()
    status_code = 200 if result.get("success") else 500
    return jsonify(result), status_code


@app.route("/waitlist/cancel/<token>", methods=["GET", "POST"])
def cancel_waitlist_entry_from_link(token):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                w.id,
                w.status,
                w.cancel_token_used,
                w.cancelled_at,
                w.client_name,
                w.client_email,
                w.client_phone,
                s.name AS service_name,
                e.full_name AS employee_name
            FROM waitlist_entries w
            LEFT JOIN services s ON s.id = w.service_id
            LEFT JOIN employees e ON e.id = w.employee_id
            WHERE w.cancel_token = ?
            LIMIT 1
        """, (token,))

        entry = cursor.fetchone()

        if not entry:
            return render_template("emails/waitlist_cancel_invalid.html"), 404

        if int(entry["cancel_token_used"] or 0) == 1 or entry["status"] == "cancelled":
            return render_template("emails/waitlist_cancel_already_used.html", entry=entry)

        if request.method == "POST":
            cursor.execute("""
                UPDATE waitlist_entries
                SET
                    status = 'cancelled',
                    cancel_token_used = 1,
                    cancelled_at = datetime('now')
                WHERE id = ?
            """, (entry["id"],))

            conn.commit()

            return render_template("emails/waitlist_cancel_success.html", entry=entry)

        return render_template(
            "emails/waitlist_cancel_confirm.html",
            entry=entry,
            token=token
        )

    finally:
        conn.close()  


@app.route("/admin/calendar")
@admin_required
def admin_calendar():
    from collections import defaultdict

    business_id = session.get("business_id", 1)

    start_str = (request.args.get("start") or "").strip()
    selected_employee_id = request.args.get("employee_id", type=int)

    today = datetime.today().date()

    try:
        if start_str:
            start_date = datetime.strptime(start_str, "%Y-%m-%d").date()
        else:
            start_date = today - timedelta(days=today.weekday())
    except ValueError:
        start_date = today - timedelta(days=today.weekday())

    end_date = start_date + timedelta(days=6)
    prev_week_start = start_date - timedelta(days=7)
    next_week_start = start_date + timedelta(days=7)

    settings = get_settings()

    def time_to_minutes(value):
        value = (value or "").strip()

        try:
            hour, minute = value.split(":")
            return int(hour) * 60 + int(minute)
        except Exception:
            return None

    def minutes_to_label(minutes):
        hour = minutes // 60
        minute = minutes % 60
        return f"{hour:02d}:{minute:02d}"

    conn = get_connection()
    cursor = conn.cursor()

    business_settings = cursor.execute(
        """
        SELECT
            company_name,
            company_address,
            contact_email,
            contact_phone,
            website_url
        FROM business_settings
        WHERE business_id = ?
        LIMIT 1
        """,
        (business_id,)
    ).fetchone()

    employees = cursor.execute(
        """
        SELECT id, full_name, role, active
        FROM employees
        WHERE business_id = ?
          AND active = 1
        ORDER BY full_name ASC
        """,
        (business_id,)
    ).fetchall()

    if not employees:
        conn.close()

        return render_template(
            "admin_calendar.html",
            page_title="Kalendarz",
            settings=settings,
            business_settings=business_settings,
            employees=[],
            selected_employee_id=None,
            selected_employee=None,
            bookings=[],
            calendar_bookings=[],
            week_days=[],
            time_slots=[],
            start_date=start_date,
            end_date=end_date,
            prev_week_start=prev_week_start,
            next_week_start=next_week_start,
            slot_interval=30,
            calendar_start_hour=8,
            calendar_end_hour=18,
            calendar_start_label="08:00",
            calendar_end_label="18:00",
        )

    employee_ids = [employee["id"] for employee in employees]

    if selected_employee_id not in employee_ids:
        selected_employee_id = employees[0]["id"]

    selected_employee = next(
        (employee for employee in employees if employee["id"] == selected_employee_id),
        None
    )

    slot_interval = 30

    if settings and "slot_interval_minutes" in settings.keys() and settings["slot_interval_minutes"]:
        try:
            slot_interval = int(settings["slot_interval_minutes"])
        except (TypeError, ValueError):
            slot_interval = 30

    slot_interval = max(5, min(180, slot_interval))

    week_days = []
    weekday_labels = ["Pon", "Wt", "Śr", "Czw", "Pt", "Sob", "Nd"]

    schedule_start_minutes = []
    schedule_end_minutes = []

    for i in range(7):
        day_date = start_date + timedelta(days=i)
        day_iso = day_date.strftime("%Y-%m-%d")

        work_data = resolve_employee_working_hours_for_date(selected_employee_id, day_iso)

        is_working_day = bool(work_data and work_data.get("available"))
        start_time = work_data.get("start_time") if work_data else None
        end_time = work_data.get("end_time") if work_data else None
        day_reason = work_data.get("reason") if work_data else ""

        day_status_label = ""
        day_status_icon = "bi-calendar-check"

        if is_working_day:
            day_status_label = f"{start_time}–{end_time}"
            day_status_icon = "bi-clock"
        else:
            if day_reason == "employee_time_off":
                time_off_data = employee_has_time_off_on_date(selected_employee_id, day_iso)

                if time_off_data.get("vacation"):
                    day_status_label = "urlop"
                    day_status_icon = "bi-airplane"
                elif time_off_data.get("sick_leave"):
                    day_status_label = "chorobowe"
                    day_status_icon = "bi-heart-pulse"
                else:
                    day_status_label = "nieobecność"
                    day_status_icon = "bi-calendar-x"

            elif day_reason == "closed_day":
                day_status_label = "dzień wyłączony"
                day_status_icon = "bi-lock"

            elif day_reason == "exception_day_off":
                day_status_label = "dzień wolny"
                day_status_icon = "bi-calendar-minus"

            elif day_reason == "weekday_off":
                day_status_label = "--:--"
                day_status_icon = "bi-calendar-x"

            elif day_reason in ["missing_hours", "exception_missing_hours"]:
                day_status_label = "brak godzin"
                day_status_icon = "bi-exclamation-circle"

            else:
                day_status_label = "--:--"
                day_status_icon = "bi-calendar-x"

        start_minutes = time_to_minutes(start_time)
        end_minutes = time_to_minutes(end_time)

        if is_working_day and start_minutes is not None and end_minutes is not None:
            schedule_start_minutes.append(start_minutes)
            schedule_end_minutes.append(end_minutes)

        week_days.append({
            "index": i,
            "iso": day_iso,
            "label": day_date.strftime("%d.%m"),
            "full_label": day_date.strftime("%d.%m.%Y"),
            "weekday": weekday_labels[i],
            "is_today": day_date == today,
            "is_working_day": is_working_day,
            "start_time": start_time or "",
            "end_time": end_time or "",
            "day_reason": day_reason,
            "day_status_label": day_status_label,
            "day_status_icon": day_status_icon,
        })

    bookings = cursor.execute(
        """
        SELECT
            b.id,
            b.booking_date,
            b.booking_time,
            b.employee_id,
            b.client_name,
            b.client_phone,
            b.client_email,
            b.status,
            b.notes,
            s.name AS service_name,
            s.price AS service_price,
            s.duration_minutes,
            e.full_name AS employee_name
        FROM bookings b
        LEFT JOIN services s ON b.service_id = s.id
        LEFT JOIN employees e ON b.employee_id = e.id
        WHERE b.business_id = ?
          AND b.employee_id = ?
          AND COALESCE(b.archived, 0) = 0
          AND b.booking_date BETWEEN ? AND ?
          AND LOWER(COALESCE(b.status, '')) IN ('new', 'confirmed')
        ORDER BY b.booking_date ASC, b.booking_time ASC, b.id ASC
        """,
        (
            business_id,
            selected_employee_id,
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d"),
        )
    ).fetchall()

    conn.close()

    booking_minutes = []

    for booking in bookings:
        start_minutes = time_to_minutes(booking["booking_time"])

        try:
            duration = int(booking["duration_minutes"] or slot_interval)
        except (TypeError, ValueError):
            duration = slot_interval

        if start_minutes is not None:
            booking_minutes.append(start_minutes)
            booking_minutes.append(start_minutes + duration)

    if schedule_start_minutes and schedule_end_minutes:
        calendar_start_minutes = min(schedule_start_minutes)
        calendar_end_minutes = max(schedule_end_minutes)
    elif booking_minutes:
        calendar_start_minutes = min(booking_minutes)
        calendar_end_minutes = max(booking_minutes)
    else:
        calendar_start_minutes = 8 * 60
        calendar_end_minutes = 18 * 60

    calendar_start_minutes = (calendar_start_minutes // slot_interval) * slot_interval

    if calendar_end_minutes % slot_interval != 0:
        calendar_end_minutes = ((calendar_end_minutes // slot_interval) + 1) * slot_interval

    if calendar_end_minutes <= calendar_start_minutes:
        calendar_end_minutes = calendar_start_minutes + (8 * 60)

    calendar_start_hour = calendar_start_minutes // 60
    calendar_end_hour = calendar_end_minutes // 60

    time_slots = []
    current_minutes = calendar_start_minutes

    while current_minutes < calendar_end_minutes:
        time_slots.append({
            "index": len(time_slots),
            "label": minutes_to_label(current_minutes),
            "minutes": current_minutes,
        })
        current_minutes += slot_interval

    day_index_by_iso = {
        day["iso"]: day["index"]
        for day in week_days
    }

    calendar_bookings = []

    for booking in bookings:
        start_minutes = time_to_minutes(booking["booking_time"])
        if start_minutes is None:
            continue

        day_index = day_index_by_iso.get(booking["booking_date"])
        if day_index is None:
            continue

        try:
            duration = int(booking["duration_minutes"] or slot_interval)
        except (TypeError, ValueError):
            duration = slot_interval

        start_slot = max(0, round((start_minutes - calendar_start_minutes) / slot_interval))
        span_slots = max(1, round(duration / slot_interval))
        end_minutes = start_minutes + duration

        calendar_bookings.append({
            "id": booking["id"],
            "day_index": day_index,
            "grid_column": day_index + 2,
            "grid_row_start": start_slot + 1,
            "grid_row_span": span_slots,
            "booking_date": booking["booking_date"],
            "booking_time": booking["booking_time"],
            "booking_end_time": minutes_to_label(end_minutes),
            "duration_minutes": duration,
            "client_name": booking["client_name"] or "Klient",
            "client_phone": booking["client_phone"] or "",
            "client_email": booking["client_email"] or "",
            "service_name": booking["service_name"] or "Usługa",
            "service_price": booking["service_price"] or "",
            "employee_name": booking["employee_name"] or "",
            "status": booking["status"] or "",
            "notes": booking["notes"] or "",
            "stack_index": 0,
            "stack_count": 1,
        })

    overlap_groups = defaultdict(list)

    for booking in calendar_bookings:
        overlap_key = (
            booking["grid_column"],
            booking["grid_row_start"],
        )
        overlap_groups[overlap_key].append(booking)

    for group in overlap_groups.values():
        group.sort(key=lambda item: (item.get("booking_time") or "", item.get("id") or 0))

        for index, booking in enumerate(group):
            booking["stack_index"] = index
            booking["stack_count"] = len(group)

    return render_template(
        "admin_calendar.html",
        page_title="Kalendarz",
        settings=settings,
        business_settings=business_settings,
        employees=employees,
        selected_employee_id=selected_employee_id,
        selected_employee=selected_employee,
        bookings=bookings,
        calendar_bookings=calendar_bookings,
        week_days=week_days,
        time_slots=time_slots,
        start_date=start_date,
        end_date=end_date,
        prev_week_start=prev_week_start,
        next_week_start=next_week_start,
        slot_interval=slot_interval,
        calendar_start_hour=calendar_start_hour,
        calendar_end_hour=calendar_end_hour,
        calendar_start_label=minutes_to_label(calendar_start_minutes),
        calendar_end_label=minutes_to_label(calendar_end_minutes),
    )


import csv
from io import TextIOWrapper

@app.route("/admin/clients/import", methods=["POST"])
@client_admin_required
def import_clients():
    file = request.files.get("file")

    if not file or not file.filename.endswith(".csv"):
        flash("Wgraj poprawny plik CSV.", "error")
        return redirect(url_for("admin_clients"))

    business_id = session.get("business_id", 1)

    imported = 0
    skipped = 0

    try:
        stream = TextIOWrapper(file.stream, encoding="utf-8")
        reader = csv.DictReader(stream)

        for row in reader:
            full_name = (row.get("full_name") or "").strip()
            phone = (row.get("phone") or "").strip()
            email = (row.get("email") or "").strip()
            notes = (row.get("notes") or "").strip()

            if not full_name:
                skipped += 1
                continue

            client_id = get_or_create_client(
                business_id=business_id,
                full_name=full_name,
                phone=phone,
                email=email
            )

            if client_id:
                imported += 1
            else:
                skipped += 1

        flash(f"Zaimportowano klientów: {imported}, pominięto: {skipped}", "success")

    except Exception as e:
        print("Błąd importu:", e)
        flash("Błąd podczas importu pliku.", "error")

    return redirect(url_for("admin_clients"))


@app.route("/consents")
def client_consents():
    token = (request.args.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    conn = get_connection()
    cursor = conn.cursor()

    client = cursor.execute("""
        SELECT *
        FROM clients
        WHERE email_verification_token = ?
        LIMIT 1
    """, (token,)).fetchone()

    if not client:
        conn.close()
        return "Nieprawidłowy link", 404

    settings = get_settings(client["business_id"])

    conn.close()

    return render_template(
        "consents.html",
        client=client,
        token=token,
        settings=settings
    )


@app.route("/consents/save", methods=["POST"])
def save_client_consents():
    token = (request.form.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    privacy = 1 if request.form.get("privacy") == "1" else 0
    marketing = 1 if request.form.get("marketing") == "1" else 0

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    client = None
    settings = None

    try:
        client = cursor.execute("""
            SELECT *
            FROM clients
            WHERE email_verification_token = ?
            LIMIT 1
        """, (token,)).fetchone()

        if not client:
            return "Nieprawidłowy token", 404

        settings = get_settings(client["business_id"])

        privacy_consent_at = client["privacy_consent_at"]
        marketing_consent_at = client["marketing_consent_at"]

        if privacy == 1 and not privacy_consent_at:
            privacy_consent_at = now_str

        if privacy == 0:
            privacy_consent_at = None

        if marketing == 1 and not marketing_consent_at:
            marketing_consent_at = now_str

        if marketing == 0:
            marketing_consent_at = None

        cursor.execute("""
            UPDATE clients
            SET
                privacy_consent = ?,
                marketing_consent = ?,
                privacy_consent_at = ?,
                marketing_consent_at = ?,
                consent_source = ?,
                updated_at = ?
            WHERE id = ?
        """, (
            privacy,
            marketing,
            privacy_consent_at,
            marketing_consent_at,
            "consent_center",
            now_str,
            client["id"]
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd save_client_consents:", e)
        return "Nie udało się zapisać zgód.", 500

    finally:
        conn.close()

    company_name = settings["company_name"] if settings and settings["company_name"] else "Salon"

    client_subject = "Potwierdzenie zapisania zgód"
    admin_subject = "Klient zaktualizował zgody"

    client_html = render_template(
        "emails/client_consents_saved.html",
        client=client,
        privacy=privacy,
        marketing=marketing,
        email_title=client_subject,
        email_heading="Potwierdzenie zapisania zgód",
        company_name=company_name,
        company_address=settings["company_address"] if settings else "",
        contact_phone=settings["contact_phone"] if settings else "",
        contact_email=settings["contact_email"] if settings else "",
        website_url=settings["website_url"] if settings else "",
    )

    client_text = (
        f"Dzień dobry {client['full_name'] or ''},\n\n"
        "Twoje zgody zostały zapisane.\n\n"
        f"RODO: {'Wyrażona' if privacy == 1 else 'Brak zgody'}\n"
        f"Marketing: {'Wyrażona' if marketing == 1 else 'Brak zgody'}\n\n"
        f"Pozdrawiamy,\n{company_name}"
    )

    admin_html = render_template(
        "emails/admin_consents_saved.html",
        client=client,
        privacy=privacy,
        marketing=marketing,
        email_title=admin_subject,
        email_heading="Aktualizacja zgód klienta",
        company_name=company_name,
        company_address=settings["company_address"] if settings else "",
        contact_phone=settings["contact_phone"] if settings else "",
        contact_email=settings["contact_email"] if settings else "",
        website_url=settings["website_url"] if settings else "",
    )

    admin_text = (
        "Klient zaktualizował zgody.\n\n"
        f"Klient: {client['full_name'] or '—'}\n"
        f"E-mail: {client['email'] or '—'}\n"
        f"Telefon: {client['phone'] or '—'}\n"
        f"RODO: {'Wyrażona' if privacy == 1 else 'Brak zgody'}\n"
        f"Marketing: {'Wyrażona' if marketing == 1 else 'Brak zgody'}\n"
    )

    try:
        if client["email"]:
            send_email_message(
                client["email"],
                client_subject,
                client_html,
                client_text
            )

        admin_email = settings["contact_email"] if settings and settings["contact_email"] else None

        if admin_email:
            send_email_message(
                admin_email,
                admin_subject,
                admin_html,
                admin_text
            )

    except Exception as e:
        print("Błąd wysyłki potwierdzenia zgód:", e)

    flash("Ustawienia zgód zostały zapisane.", "success")
    return redirect(url_for("client_consents", token=token))

@app.route("/unsubscribe-booking-emails")
def unsubscribe_booking_emails_page():
    token = (request.args.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    conn = get_connection()
    cursor = conn.cursor()

    client = cursor.execute("""
        SELECT *
        FROM clients
        WHERE email_verification_token = ?
        LIMIT 1
    """, (token,)).fetchone()

    if not client:
        conn.close()
        return "Nieprawidłowy link", 404

    settings = get_settings(client["business_id"])

    conn.close()

    return render_template(
        "unsubscribe_booking_emails.html",
        client=client,
        token=token,
        settings=settings
    )


@app.route("/unsubscribe-booking-emails/confirm", methods=["POST"])
def unsubscribe_booking_emails_confirm():
    token = (request.form.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        client = cursor.execute("""
            SELECT *
            FROM clients
            WHERE email_verification_token = ?
            LIMIT 1
        """, (token,)).fetchone()

        if not client:
            return "Nieprawidłowy token", 404

        cursor.execute("""
            UPDATE clients
            SET
                email_notifications_enabled = 0,
                email_notifications_disabled_at = ?,
                email_verified = 0,
                email_verified_at = NULL,
                updated_at = ?
            WHERE id = ?
        """, (now_str, now_str, client["id"]))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd unsubscribe_booking_emails_confirm:", e)
        return "Nie udało się zapisać rezygnacji.", 500

    finally:
        conn.close()

    return redirect(url_for("unsubscribe_booking_emails_page", token=token, saved="1"))


@app.route("/withdraw-marketing-consent")
def withdraw_marketing_consent_page():
    token = (request.args.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    conn = get_connection()
    cursor = conn.cursor()

    client = cursor.execute("""
        SELECT *
        FROM clients
        WHERE email_verification_token = ?
        LIMIT 1
    """, (token,)).fetchone()

    if not client:
        conn.close()
        return "Nieprawidłowy link", 404

    settings = get_settings(client["business_id"])

    conn.close()

    return render_template(
        "withdraw_marketing_consent.html",
        client=client,
        token=token,
        settings=settings
    )


@app.route("/withdraw-marketing-consent/confirm", methods=["POST"])
def withdraw_marketing_consent_confirm():
    token = (request.form.get("token") or "").strip()

    if not token:
        return "Brak tokenu", 400

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        client = cursor.execute("""
            SELECT *
            FROM clients
            WHERE email_verification_token = ?
            LIMIT 1
        """, (token,)).fetchone()

        if not client:
            return "Nieprawidłowy token", 404

        cursor.execute("""
            UPDATE clients
            SET
                marketing_consent = 0,
                marketing_consent_at = NULL,
                consent_source = 'marketing_withdraw_link',
                updated_at = ?
            WHERE id = ?
        """, (now_str, client["id"]))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd withdraw_marketing_consent_confirm:", e)
        return "Nie udało się wycofać zgody marketingowej.", 500

    finally:
        conn.close()

    return redirect(url_for("withdraw_marketing_consent_page", token=token, saved="1"))


@app.route("/admin/bookings/custom/availability")
@admin_required
def custom_booking_availability():
    business_id = session.get("business_id", 1)

    booking_date = (request.args.get("date") or "").strip()
    employee_id = (request.args.get("employee_id") or "").strip()
    duration_raw = (request.args.get("duration") or "30").strip()

    if not booking_date or not employee_id:
        return jsonify({
            "success": False,
            "slots": [],
            "message": "Brakuje daty lub pracownika."
        }), 400

    try:
        duration = int(duration_raw)
    except ValueError:
        duration = 30

    if duration <= 0:
        duration = 30

    conn = get_connection()
    cursor = conn.cursor()

    try:
        slots = get_available_custom_booking_slots(
            cursor=cursor,
            business_id=business_id,
            employee_id=int(employee_id),
            booking_date=booking_date,
            duration_minutes=duration
        )

        return jsonify({
            "success": True,
            "slots": slots
        })

    except Exception as e:
        print("CUSTOM BOOKING AVAILABILITY ERROR:", e)
        return jsonify({
            "success": False,
            "slots": [],
            "message": "Nie udało się pobrać dostępnych godzin."
        }), 500

    finally:
        conn.close()    
    

@app.route("/admin/clients/<int:client_id>/blacklist-toggle", methods=["POST"])
@admin_required
def toggle_client_blacklist(client_id):
    business_id = session.get("business_id", 1)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT id, COALESCE(blacklisted, 0) AS blacklisted
            FROM clients
            WHERE id = ?
              AND business_id = ?
            LIMIT 1
        """, (client_id, business_id))

        client = cursor.fetchone()

        if not client:
            flash("Nie znaleziono klienta.", "error")
            return redirect(url_for("admin_clients"))

        current = int(client["blacklisted"] or 0)
        new_value = 0 if current == 1 else 1

        if new_value == 1:
            cursor.execute("""
                UPDATE clients
                SET blacklisted = 1,
                    blacklist_reason = COALESCE(NULLIF(blacklist_reason, ''), 'Dodano ręcznie'),
                    blacklisted_at = datetime('now')
                WHERE id = ?
                  AND business_id = ?
            """, (client_id, business_id))

            flash("Klient został dodany do czarnej listy.", "success")

        else:
            cursor.execute("""
                UPDATE clients
                SET blacklisted = 0,
                    blacklist_reason = NULL,
                    blacklisted_at = NULL
                WHERE id = ?
                  AND business_id = ?
            """, (client_id, business_id))

            flash("Klient został usunięty z czarnej listy.", "success")

        conn.commit()

    except Exception as e:
        conn.rollback()
        print("Błąd toggle_client_blacklist:", e)
        flash("Nie udało się zmienić statusu czarnej listy.", "error")

    finally:
        conn.close()

    return redirect(url_for("admin_clients"))


@app.route("/admin/bookings/custom/create", methods=["POST"])
@admin_required
def create_custom_booking():
    business_id = session.get("business_id", 1)

    booking_date = (request.form.get("booking_date") or "").strip()
    booking_time = (request.form.get("booking_time") or "").strip()
    employee_id = (request.form.get("employee_id") or "").strip()

    service_name = (request.form.get("service_name") or "").strip()
    price = (request.form.get("price") or "").strip()
    duration_raw = (request.form.get("duration") or "").strip()

    client_name = (request.form.get("client_name") or "").strip()
    client_email = (request.form.get("client_email") or "").strip()
    client_phone = (request.form.get("client_phone") or "").strip()
    notes = (request.form.get("notes") or "").strip()

    if not booking_date or not booking_time or not employee_id or not service_name or not client_name:
        flash("Uzupełnij wymagane pola rezerwacji niestandardowej.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        duration = int(duration_raw or 30)
    except ValueError:
        duration = 30

    if duration <= 0:
        duration = 30

    if not price:
        price = "0 PLN"
    elif "PLN" not in price.upper():
        price = f"{price} PLN"

    conn = get_connection()
    cursor = conn.cursor()

    try:
        custom_service_id = get_or_create_custom_service_id(cursor, business_id)

        client = None

        if client_email:
            client = cursor.execute("""
                SELECT id
                FROM clients
                WHERE business_id = ?
                  AND LOWER(email) = LOWER(?)
                LIMIT 1
            """, (business_id, client_email)).fetchone()

        if not client and client_phone:
            client = cursor.execute("""
                SELECT id
                FROM clients
                WHERE business_id = ?
                  AND phone = ?
                LIMIT 1
            """, (business_id, client_phone)).fetchone()

        if client:
            client_id = client["id"]

            cursor.execute("""
                UPDATE clients
                SET
                    full_name = COALESCE(NULLIF(?, ''), full_name),
                    phone = COALESCE(NULLIF(?, ''), phone),
                    email = COALESCE(NULLIF(?, ''), email),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                  AND business_id = ?
            """, (
                client_name,
                client_phone,
                client_email,
                client_id,
                business_id
            ))

        else:
            cursor.execute("""
                INSERT INTO clients (
                    business_id,
                    full_name,
                    phone,
                    email,
                    email_verified,
                    client_status,
                    privacy_consent,
                    marketing_consent,
                    consent_source,
                    privacy_notice_confirmed,
                    created_at,
                    updated_at
                ) VALUES (?, ?, ?, ?, 0, 'standard', 0, 0, 'admin_custom_booking', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            """, (
                business_id,
                client_name,
                client_phone,
                client_email
            ))

            client_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO bookings (
                business_id,
                service_id,
                employee_id,
                client_id,
                client_name,
                client_email,
                client_phone,
                booking_date,
                booking_time,
                booking_type,
                custom_service_name,
                custom_service_price,
                custom_service_duration,
                notes,
                status,
                archived,
                privacy_consent,
                marketing_consent,
                consents_created_at,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'custom', ?, ?, ?, ?, 'confirmed', 0, 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """, (
            business_id,
            custom_service_id,
            int(employee_id),
            client_id,
            client_name,
            client_email,
            client_phone,
            booking_date,
            booking_time,
            service_name,
            price,
            duration,
            notes
        ))

        conn.commit()

        flash("Rezerwacja niestandardowa została dodana jako potwierdzona.", "success")
        return redirect(url_for("admin_dashboard"))

    except Exception as e:
        conn.rollback()
        print("CREATE CUSTOM BOOKING ERROR:", e)
        flash("Nie udało się zapisać rezerwacji niestandardowej.", "error")
        return redirect(url_for("admin_dashboard"))

    finally:
        conn.close()



@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    business_id = session.get("business_id", 1)
    period = (request.args.get("period") or "30").strip()

    settings = get_settings(business_id)
    analytics_data = get_analytics_summary(business_id, period)

    return render_template(
        "admin_analytics.html",
        page_title="Statystyki",
        settings=settings,
        **analytics_data
    )


if __name__ == "__main__":
    app.run(debug=True)