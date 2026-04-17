import secrets
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app, render_template, url_for

from services.db import get_connection


TEST_FROM_EMAIL = "office@sddestonie.com"


def generate_email_verification_token() -> str:
    return secrets.token_urlsafe(32)


def build_client_verification_link(token: str) -> str:
    return url_for("verify_client_email", token=token, _external=True)


def send_email_message(to_email: str, subject: str, html_body: str, text_body: str = "") -> bool:
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


def get_booking_verification_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute("""
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
        """, (booking_id,)).fetchone()

        return row
    finally:
        conn.close()


def get_waitlist_verification_payload(waitlist_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        row = cursor.execute("""
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
        """, (waitlist_id,)).fetchone()

        return row
    finally:
        conn.close()


def assign_client_verification_token(client_id: int) -> str | None:
    token = generate_email_verification_token()
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            UPDATE clients
            SET
                email_verification_token = ?,
                email_verification_sent_at = ?,
                email_verified = 0
            WHERE id = ?
        """, (token, datetime.utcnow().isoformat(), client_id))
        conn.commit()
        return token
    except Exception as e:
        conn.rollback()
        print("TOKEN ASSIGN ERROR:", e)
        return None
    finally:
        conn.close()


def send_booking_verification_email(booking_id: int) -> bool:
    payload = get_booking_verification_payload(booking_id)
    if not payload:
        return False

    client_id = payload["client_id"]
    client_email = (payload["client_email"] or "").strip()

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
        verification_link=verification_link
    )

    text_body = (
        f"Twoja rezerwacja została zapisana.\n"
        f"Aby otrzymywać kolejne wiadomości dotyczące rezerwacji, potwierdź adres e-mail:\n"
        f"{verification_link}"
    )

    return send_email_message(client_email, subject, html_body, text_body)


def send_waitlist_verification_email(waitlist_id: int) -> bool:
    payload = get_waitlist_verification_payload(waitlist_id)
    if not payload:
        return False

    client_id = payload["client_id"]
    client_email = (payload["client_email"] or "").strip()

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
        f"Twój zapis na listę oczekujących został przyjęty.\n"
        f"Aby otrzymywać kolejne wiadomości dotyczące zgłoszenia, potwierdź adres e-mail:\n"
        f"{verification_link}"
    )

    return send_email_message(client_email, subject, html_body, text_body)