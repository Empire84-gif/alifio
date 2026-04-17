import secrets
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app, render_template, url_for
from markupsafe import escape

from services.db import get_connection


TEST_FROM_EMAIL = "office@sddestonie.com"


# =========================================================
# BASIC HELPERS
# =========================================================

def generate_email_verification_token() -> str:
    return secrets.token_urlsafe(32)


def build_client_verification_link(token: str) -> str:
    return url_for("verify_client_email", token=token, _external=True)


def format_date_pl(date_value: str | None) -> str:
    value = (date_value or "").strip()
    if not value:
        return "—"

    parts = value.split("-")
    if len(parts) == 3:
        return f"{parts[2]}.{parts[1]}.{parts[0]}"

    return value


def format_waitlist_date_range(date_from: str | None, date_to: str | None) -> str:
    from_display = format_date_pl(date_from)
    to_display = format_date_pl(date_to)

    if date_from and date_to:
        return f"{from_display} — {to_display}"
    if date_from:
        return from_display
    if date_to:
        return to_display
    return "—"


def format_waitlist_time_range(time_from: str | None, time_to: str | None) -> str:
    from_value = (time_from or "").strip()
    to_value = (time_to or "").strip()

    if from_value and to_value:
        return f"{from_value} — {to_value}"
    if from_value:
        return from_value
    if to_value:
        return to_value
    return "—"


def normalize_email(value: str | None) -> str:
    return (value or "").strip()


def unique_email_list(*emails: str | None) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()

    for email in emails:
        normalized = normalize_email(email)
        if not normalized:
            continue

        key = normalized.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(normalized)

    return result


# =========================================================
# SMTP
# =========================================================

def send_email_message(
    to_email: str,
    subject: str,
    html_body: str,
    text_body: str = ""
) -> bool:
    smtp_host = current_app.config.get("MAIL_SMTP_HOST")
    smtp_port = current_app.config.get("MAIL_SMTP_PORT")
    smtp_username = current_app.config.get("MAIL_SMTP_USERNAME")
    smtp_password = current_app.config.get("MAIL_SMTP_PASSWORD")
    smtp_use_tls = current_app.config.get("MAIL_SMTP_USE_TLS", False)
    smtp_use_ssl = current_app.config.get("MAIL_SMTP_USE_SSL", False)

    from_email = current_app.config.get("MAIL_FROM_EMAIL", TEST_FROM_EMAIL)

    if not smtp_host or not smtp_port or not smtp_username or not smtp_password:
        print("MAIL CONFIG MISSING")
        print("TO:", to_email)
        print("SUBJECT:", subject)
        print("HTML BODY:", html_body)
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))

    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        if smtp_use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(smtp_username, smtp_password)
                server.sendmail(from_email, [to_email], msg.as_string())
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_use_tls:
                    server.starttls()
                server.login(smtp_username, smtp_password)
                server.sendmail(from_email, [to_email], msg.as_string())

        return True

    except Exception as e:
        print("EMAIL SEND ERROR:", e)
        return False


def send_email_to_many(
    recipients: list[str],
    subject: str,
    html_body: str,
    text_body: str = ""
) -> bool:
    clean_recipients = unique_email_list(*recipients)
    if not clean_recipients:
        return False

    sent_any = False
    for recipient in clean_recipients:
        if send_email_message(recipient, subject, html_body, text_body):
            sent_any = True

    return sent_any


# =========================================================
# CLIENT VERIFICATION TOKENS
# =========================================================

def assign_client_verification_token(client_id: int) -> str | None:
    token = generate_email_verification_token()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            UPDATE clients
            SET
                email_verification_token = ?,
                email_verification_sent_at = ?,
                email_verified = 0
            WHERE id = ?
            """,
            (token, datetime.utcnow().isoformat(), client_id)
        )
        conn.commit()
        return token

    except Exception as e:
        conn.rollback()
        print("TOKEN ASSIGN ERROR:", e)
        return None

    finally:
        conn.close()


# =========================================================
# PAYLOADS
# =========================================================

def get_booking_verification_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute(
            """
            SELECT
                b.id AS booking_id,
                b.client_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                s.name AS service_name,
                e.full_name AS employee_name,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

        return row

    finally:
        conn.close()


def get_waitlist_verification_payload(waitlist_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute(
            """
            SELECT
                w.id AS waitlist_id,
                w.client_id,
                w.client_name,
                w.client_email,
                w.client_phone,
                w.preferred_date_from,
                w.preferred_date_to,
                w.preferred_time_from,
                w.preferred_time_to,
                s.name AS service_name,
                e.full_name AS employee_name,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM waitlist_entries w
            LEFT JOIN services s ON s.id = w.service_id
            LEFT JOIN employees e ON e.id = w.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE w.id = ?
            LIMIT 1
            """,
            (waitlist_id,)
        ).fetchone()

        return row

    finally:
        conn.close()


def get_booking_internal_notification_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute(
            """
            SELECT
                b.id AS booking_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.notes,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

        return row

    finally:
        conn.close()


def get_waitlist_internal_notification_payload(waitlist_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute(
            """
            SELECT
                w.id AS waitlist_id,
                w.client_name,
                w.client_email,
                w.client_phone,
                w.preferred_date_from,
                w.preferred_date_to,
                w.preferred_time_from,
                w.preferred_time_to,
                w.notes,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM waitlist_entries w
            LEFT JOIN services s ON s.id = w.service_id
            LEFT JOIN employees e ON e.id = w.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE w.id = ?
            LIMIT 1
            """,
            (waitlist_id,)
        ).fetchone()

        return row

    finally:
        conn.close()


def get_booking_cancellation_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute(
            """
            SELECT
                b.id AS booking_id,
                b.client_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.contact_email,
                bs.contact_phone
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

        return row

    finally:
        conn.close()


# =========================================================
# BOOKING / WAITLIST VERIFICATION EMAILS
# =========================================================

def send_booking_verification_email(booking_id: int, cancel_url: str | None = None) -> bool:
    payload = get_booking_verification_payload(booking_id)
    if not payload:
        return False

    client_id = payload["client_id"]
    client_email = normalize_email(payload["client_email"])

    if not client_id or not client_email:
        return False

    token = assign_client_verification_token(client_id)
    if not token:
        return False

    verification_link = build_client_verification_link(token)
    subject = "Potwierdzenie rezerwacji i adresu e-mail"

    html_body = render_template(
        "emails/booking_verification.html",
        data=payload,
        verification_link=verification_link,
        cancel_url=cancel_url
    )

    text_body = (
        "Twoja rezerwacja została zapisana.\n"
        "Aby otrzymywać kolejne wiadomości dotyczące rezerwacji, potwierdź adres e-mail:\n"
        f"{verification_link}"
    )

    if cancel_url:
        text_body += (
            "\n\nJeśli chcesz anulować tę rezerwację, użyj poniższego linku:\n"
            f"{cancel_url}"
        )

    return send_email_message(client_email, subject, html_body, text_body)


def send_waitlist_verification_email(waitlist_id: int) -> bool:
    payload = get_waitlist_verification_payload(waitlist_id)
    if not payload:
        return False

    client_id = payload["client_id"]
    client_email = normalize_email(payload["client_email"])

    if not client_id or not client_email:
        return False

    token = assign_client_verification_token(client_id)
    if not token:
        return False

    verification_link = build_client_verification_link(token)
    subject = "Potwierdzenie zapisu na listę oczekujących i adresu e-mail"

    html_body = render_template(
        "emails/waitlist_verification.html",
        data=payload,
        verification_link=verification_link
    )

    text_body = (
        "Twój zapis na listę oczekujących został przyjęty.\n"
        "Aby otrzymywać kolejne wiadomości dotyczące zgłoszenia, potwierdź adres e-mail:\n"
        f"{verification_link}"
    )

    return send_email_message(client_email, subject, html_body, text_body)


# =========================================================
# INTERNAL NOTIFICATIONS - HTML/TEXT BUILDERS
# =========================================================

def build_booking_internal_email_html(payload, recipient_label: str) -> str:
    company_name = escape(payload["company_name"] or "Salon")
    service_name = escape(payload["service_name"] or "—")
    employee_name = escape(payload["employee_name"] or "—")
    client_name = escape(payload["client_name"] or "—")
    client_email = escape(payload["client_email"] or "—")
    client_phone = escape(payload["client_phone"] or "—")
    booking_date = escape(format_date_pl(payload["booking_date"]))
    booking_time = escape(payload["booking_time"] or "—")
    notes = escape((payload["notes"] or "").strip() or "Brak notatki.")
    recipient_label = escape(recipient_label)

    return f"""
    <div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6;color:#111;">
      <p>Cześć,</p>
      <p>
        w systemie <strong>{company_name}</strong> została właśnie zapisana nowa rezerwacja.
      </p>
      <p><strong>Odbiorca powiadomienia:</strong> {recipient_label}</p>
      <table cellpadding="8" cellspacing="0" border="0" style="border-collapse:collapse;">
        <tr><td><strong>Usługa:</strong></td><td>{service_name}</td></tr>
        <tr><td><strong>Specjalista:</strong></td><td>{employee_name}</td></tr>
        <tr><td><strong>Klient:</strong></td><td>{client_name}</td></tr>
        <tr><td><strong>E-mail klienta:</strong></td><td>{client_email}</td></tr>
        <tr><td><strong>Telefon klienta:</strong></td><td>{client_phone}</td></tr>
        <tr><td><strong>Data:</strong></td><td>{booking_date}</td></tr>
        <tr><td><strong>Godzina:</strong></td><td>{booking_time}</td></tr>
        <tr><td><strong>Notatki:</strong></td><td>{notes}</td></tr>
      </table>
      <p>Pozdrawiamy,<br>Alifio</p>
    </div>
    """


def build_booking_internal_email_text(payload, recipient_label: str) -> str:
    return (
        f"Nowa rezerwacja w systemie {payload['company_name'] or 'Salon'}\n\n"
        f"Odbiorca powiadomienia: {recipient_label}\n"
        f"Usługa: {payload['service_name'] or '—'}\n"
        f"Specjalista: {payload['employee_name'] or '—'}\n"
        f"Klient: {payload['client_name'] or '—'}\n"
        f"E-mail klienta: {payload['client_email'] or '—'}\n"
        f"Telefon klienta: {payload['client_phone'] or '—'}\n"
        f"Data: {format_date_pl(payload['booking_date'])}\n"
        f"Godzina: {payload['booking_time'] or '—'}\n"
        f"Notatki: {(payload['notes'] or '').strip() or 'Brak notatki.'}\n"
    )


def build_waitlist_internal_email_html(payload, recipient_label: str) -> str:
    company_name = escape(payload["company_name"] or "Salon")
    service_name = escape(payload["service_name"] or "—")
    employee_name = escape(payload["employee_name"] or "—")
    client_name = escape(payload["client_name"] or "—")
    client_email = escape(payload["client_email"] or "—")
    client_phone = escape(payload["client_phone"] or "—")
    date_range = escape(format_waitlist_date_range(
        payload["preferred_date_from"],
        payload["preferred_date_to"]
    ))
    time_range = escape(format_waitlist_time_range(
        payload["preferred_time_from"],
        payload["preferred_time_to"]
    ))
    notes = escape((payload["notes"] or "").strip() or "Brak notatki.")
    recipient_label = escape(recipient_label)

    return f"""
    <div style="font-family:Arial,sans-serif;font-size:15px;line-height:1.6;color:#111;">
      <p>Cześć,</p>
      <p>
        w systemie <strong>{company_name}</strong> pojawił się nowy wpis na listę oczekujących.
      </p>
      <p><strong>Odbiorca powiadomienia:</strong> {recipient_label}</p>
      <table cellpadding="8" cellspacing="0" border="0" style="border-collapse:collapse;">
        <tr><td><strong>Usługa:</strong></td><td>{service_name}</td></tr>
        <tr><td><strong>Specjalista:</strong></td><td>{employee_name}</td></tr>
        <tr><td><strong>Klient:</strong></td><td>{client_name}</td></tr>
        <tr><td><strong>E-mail klienta:</strong></td><td>{client_email}</td></tr>
        <tr><td><strong>Telefon klienta:</strong></td><td>{client_phone}</td></tr>
        <tr><td><strong>Zakres dat:</strong></td><td>{date_range}</td></tr>
        <tr><td><strong>Zakres godzin:</strong></td><td>{time_range}</td></tr>
        <tr><td><strong>Notatki:</strong></td><td>{notes}</td></tr>
      </table>
      <p>Pozdrawiamy,<br>Alifio</p>
    </div>
    """


def build_waitlist_internal_email_text(payload, recipient_label: str) -> str:
    return (
        f"Nowy wpis na listę oczekujących w systemie {payload['company_name'] or 'Salon'}\n\n"
        f"Odbiorca powiadomienia: {recipient_label}\n"
        f"Usługa: {payload['service_name'] or '—'}\n"
        f"Specjalista: {payload['employee_name'] or '—'}\n"
        f"Klient: {payload['client_name'] or '—'}\n"
        f"E-mail klienta: {payload['client_email'] or '—'}\n"
        f"Telefon klienta: {payload['client_phone'] or '—'}\n"
        f"Zakres dat: {format_waitlist_date_range(payload['preferred_date_from'], payload['preferred_date_to'])}\n"
        f"Zakres godzin: {format_waitlist_time_range(payload['preferred_time_from'], payload['preferred_time_to'])}\n"
        f"Notatki: {(payload['notes'] or '').strip() or 'Brak notatki.'}\n"
    )


# =========================================================
# INTERNAL NOTIFICATIONS - SENDING
# =========================================================

def send_booking_internal_notifications(booking_id: int) -> dict:
    payload = get_booking_internal_notification_payload(booking_id)
    if not payload:
        return {"salon_sent": False, "employee_sent": False}

    company_name = (payload["company_name"] or "Salon").strip()
    salon_email = normalize_email(payload["contact_email"])
    employee_email = normalize_email(payload["employee_email"])

    result = {
        "salon_sent": False,
        "employee_sent": False
    }

    if salon_email:
        result["salon_sent"] = send_email_message(
            salon_email,
            f"Nowa rezerwacja — {company_name}",
            build_booking_internal_email_html(payload, "Salon"),
            build_booking_internal_email_text(payload, "Salon")
        )

    if employee_email:
        result["employee_sent"] = send_email_message(
            employee_email,
            f"Nowa rezerwacja — {company_name}",
            build_booking_internal_email_html(payload, "Pracownik"),
            build_booking_internal_email_text(payload, "Pracownik")
        )

    return result


def send_waitlist_internal_notifications(waitlist_id: int) -> dict:
    payload = get_waitlist_internal_notification_payload(waitlist_id)
    if not payload:
        return {"salon_sent": False, "employee_sent": False}

    company_name = (payload["company_name"] or "Salon").strip()
    salon_email = normalize_email(payload["contact_email"])
    employee_email = normalize_email(payload["employee_email"])

    result = {
        "salon_sent": False,
        "employee_sent": False
    }

    if salon_email:
        result["salon_sent"] = send_email_message(
            salon_email,
            f"Nowa lista oczekujących — {company_name}",
            build_waitlist_internal_email_html(payload, "Salon"),
            build_waitlist_internal_email_text(payload, "Salon")
        )

    if employee_email:
        result["employee_sent"] = send_email_message(
            employee_email,
            f"Nowa lista oczekujących — {company_name}",
            build_waitlist_internal_email_html(payload, "Pracownik"),
            build_waitlist_internal_email_text(payload, "Pracownik")
        )

    return result


# =========================================================
# CANCELLATION EMAILS
# =========================================================

def send_booking_cancellation_confirmation_email(booking_data: dict) -> bool:
    if not booking_data:
        return False

    client_email = normalize_email(booking_data.get("client_email"))
    if not client_email:
        return False

    subject = "Potwierdzenie anulowania rezerwacji"

    html_body = render_template(
        "emails/booking_cancel_confirmation.html",
        data=booking_data
    )

    text_body = (
        "Twoja rezerwacja została anulowana.\n\n"
        f"Usługa: {(booking_data.get('service_name') or '—').strip()}\n"
        f"Specjalista: {(booking_data.get('employee_name') or '—').strip()}\n"
        f"Data: {format_date_pl(booking_data.get('booking_date'))}\n"
        f"Godzina: {(booking_data.get('booking_time') or '—').strip()}\n"
    )

    return send_email_message(
        to_email=client_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body
    )


def send_booking_cancellation_internal_notifications(booking_data: dict) -> bool:
    if not booking_data:
        return False

    company_name = (booking_data.get("company_name") or "Booking System").strip()
    service_name = (booking_data.get("service_name") or "—").strip()
    employee_name = (booking_data.get("employee_name") or "—").strip()
    client_name = (booking_data.get("client_name") or "—").strip()
    client_email = normalize_email(booking_data.get("client_email"))
    client_phone = (booking_data.get("client_phone") or "").strip()
    booking_date = format_date_pl(booking_data.get("booking_date"))
    booking_time = (booking_data.get("booking_time") or "—").strip()

    recipients = unique_email_list(
        booking_data.get("contact_email"),
        booking_data.get("employee_email")
    )

    if not recipients:
        return False

    subject = f"Anulowano rezerwację — {client_name}"

    html_body = render_template(
        "emails/booking_cancel_internal.html",
        data={
            "company_name": company_name,
            "service_name": service_name,
            "employee_name": employee_name,
            "client_name": client_name,
            "client_email": client_email,
            "client_phone": client_phone,
            "booking_date": booking_date,
            "booking_time": booking_time,
        }
    )

    text_body = (
        "Anulowano rezerwację.\n\n"
        f"Klient: {client_name}\n"
        f"Usługa: {service_name}\n"
        f"Specjalista: {employee_name}\n"
        f"Data: {booking_date}\n"
        f"Godzina: {booking_time}\n"
        f"E-mail: {client_email or '—'}\n"
        f"Telefon: {client_phone or '—'}"
    )

    return send_email_to_many(
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        text_body=text_body
    )


def send_booking_cancellation_notifications(booking_id: int) -> bool:
    payload = get_booking_cancellation_payload(booking_id)
    if not payload:
        return False

    sent_any = False

    if send_booking_cancellation_internal_notifications(dict(payload)):
        sent_any = True

    if normalize_email(payload["client_email"]):
        if send_booking_cancellation_confirmation_email(dict(payload)):
            sent_any = True

    return sent_any