import os
import secrets
import smtplib
from datetime import datetime
from email.message import EmailMessage
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

        lowered = normalized.lower()
        if lowered in seen:
            continue

        seen.add(lowered)
        result.append(normalized)

    return result


def row_to_dict(payload) -> dict:
    if not payload:
        return {}

    if isinstance(payload, dict):
        return payload

    try:
        return dict(payload)
    except Exception:
        return {}


def get_company_display_name(value: str | None) -> str:
    company_name = (value or "").strip()
    return company_name if company_name else "Alifio"


def get_company_team_signature(value: str | None) -> str:
    company_name = get_company_display_name(value)
    return f"Pozdrawiamy,\n{company_name}"


def format_consent_status(value) -> str:
    return "Tak" if int(value or 0) == 1 else "Nie"


def build_company_email_context(payload: dict) -> dict:
    payload = row_to_dict(payload)

    return {
        "company_name": get_company_display_name(payload.get("company_name")),
        "company_address": (payload.get("company_address") or "").strip(),
        "contact_phone": (payload.get("contact_phone") or "").strip(),
        "contact_email": (payload.get("contact_email") or "").strip(),
        "website_url": (payload.get("website_url") or "").strip(),
    }


def build_company_footer_html(payload: dict) -> str:
    company = build_company_email_context(payload)

    rows = []

    if company["company_address"]:
        rows.append(escape(company["company_address"]))

    if company["contact_phone"]:
        rows.append(f"Tel.: {escape(company['contact_phone'])}")

    if company["contact_email"]:
        rows.append(f"E-mail: {escape(company['contact_email'])}")

    if company["website_url"]:
        safe_url = escape(company["website_url"])
        rows.append(f'Strona: <a href="{safe_url}" style="color:#7C6B5F; text-decoration:none;">{safe_url}</a>')

    if not rows:
        return ""

    return (
        '<div style="margin-top:14px; padding-top:14px; border-top:1px solid #E2D8CE; '
        'font-size:12px; line-height:1.75; color:#7C6B5F;">'
        + "<br>".join(rows)
        + "</div>"
    )


def build_company_footer_text(payload: dict) -> str:
    company = build_company_email_context(payload)

    rows = []

    if company["company_address"]:
        rows.append(company["company_address"])

    if company["contact_phone"]:
        rows.append(f"Tel.: {company['contact_phone']}")

    if company["contact_email"]:
        rows.append(f"E-mail: {company['contact_email']}")

    if company["website_url"]:
        rows.append(f"Strona: {company['website_url']}")

    if not rows:
        return ""

    return "\n" + "\n".join(rows)


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


def send_email_smtp(to_email, subject, body):
    to_email = (to_email or "").strip()
    subject = (subject or "").strip()
    body = (body or "").strip()

    if not to_email:
        raise ValueError("Brak adresu odbiorcy e-mail.")

    mail_from_email = os.getenv("MAIL_FROM_EMAIL", "admin@handkeholding.com").strip()
    mail_smtp_host = os.getenv("MAIL_SMTP_HOST", "smtp.zone.eu").strip()
    mail_smtp_port = int(os.getenv("MAIL_SMTP_PORT", "465"))
    mail_smtp_username = os.getenv("MAIL_SMTP_USERNAME", "admin@handkeholding.com").strip()
    mail_smtp_password = os.getenv("MAIL_SMTP_PASSWORD", "").strip()
    mail_smtp_use_tls = os.getenv("MAIL_SMTP_USE_TLS", "false").lower() == "true"
    mail_smtp_use_ssl = os.getenv("MAIL_SMTP_USE_SSL", "true").lower() == "true"

    if not mail_smtp_host:
        raise ValueError("Brak MAIL_SMTP_HOST.")
    if not mail_smtp_username:
        raise ValueError("Brak MAIL_SMTP_USERNAME.")
    if not mail_smtp_password:
        raise ValueError("Brak MAIL_SMTP_PASSWORD.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = mail_from_email
    msg["To"] = to_email
    msg.set_content(body)

    if mail_smtp_use_ssl:
        with smtplib.SMTP_SSL(mail_smtp_host, mail_smtp_port, timeout=20) as server:
            server.login(mail_smtp_username, mail_smtp_password)
            server.send_message(msg)
    else:
        with smtplib.SMTP(mail_smtp_host, mail_smtp_port, timeout=20) as server:
            server.ehlo()

            if mail_smtp_use_tls:
                server.starttls()
                server.ehlo()

            server.login(mail_smtp_username, mail_smtp_password)
            server.send_message(msg)


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
        return cursor.execute(
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
                bs.company_address,
                bs.contact_email,
                bs.contact_phone,
                bs.website_url
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

    finally:
        conn.close()


def get_waitlist_verification_payload(waitlist_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        return cursor.execute(
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
                bs.company_address,
                bs.contact_email,
                bs.contact_phone,
                bs.website_url
            FROM waitlist_entries w
            LEFT JOIN services s ON s.id = w.service_id
            LEFT JOIN employees e ON e.id = w.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE w.id = ?
            LIMIT 1
            """,
            (waitlist_id,)
        ).fetchone()

    finally:
        conn.close()


def get_booking_internal_notification_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        return cursor.execute(
            """
            SELECT
                b.id AS booking_id,
                b.client_name,
                b.client_email,
                b.client_phone,
                b.booking_date,
                b.booking_time,
                b.notes,
                b.privacy_consent,
                b.marketing_consent,
                b.consents_created_at,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.company_address,
                bs.contact_email,
                bs.contact_phone,
                bs.website_url
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

    finally:
        conn.close()


def get_waitlist_internal_notification_payload(waitlist_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        return cursor.execute(
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
                w.privacy_consent,
                w.marketing_consent,
                w.consents_created_at,
                s.name AS service_name,
                e.full_name AS employee_name,
                e.email AS employee_email,
                bs.company_name,
                bs.company_address,
                bs.contact_email,
                bs.contact_phone,
                bs.website_url
            FROM waitlist_entries w
            LEFT JOIN services s ON s.id = w.service_id
            LEFT JOIN employees e ON e.id = w.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE w.id = ?
            LIMIT 1
            """,
            (waitlist_id,)
        ).fetchone()

    finally:
        conn.close()


def get_booking_cancellation_payload(booking_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    try:
        return cursor.execute(
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
                bs.company_address,
                bs.contact_email,
                bs.contact_phone,
                bs.website_url
            FROM bookings b
            LEFT JOIN services s ON s.id = b.service_id
            LEFT JOIN employees e ON e.id = b.employee_id
            LEFT JOIN business_settings bs ON bs.id = 1
            WHERE b.id = ?
            LIMIT 1
            """,
            (booking_id,)
        ).fetchone()

    finally:
        conn.close()


# =========================================================
# BOOKING / WAITLIST VERIFICATION EMAILS
# =========================================================

def send_booking_verification_email(booking_id: int, cancel_url: str | None = None) -> bool:
    payload = get_booking_verification_payload(booking_id)
    if not payload:
        return False

    payload = row_to_dict(payload)

    client_id = payload.get("client_id")
    client_email = normalize_email(payload.get("client_email"))

    if not client_id or not client_email:
        return False

    token = assign_client_verification_token(client_id)
    if not token:
        return False

    verification_link = build_client_verification_link(token)
    company_name = get_company_display_name(payload.get("company_name"))
    team_signature = get_company_team_signature(payload.get("company_name"))
    client_name = (payload.get("client_name") or "Kliencie").strip()
    company_ctx = build_company_email_context(payload)

    subject = "Potwierdź adres e-mail do komunikacji w sprawie rezerwacji"

    html_body = render_template(
        "emails/booking_verification.html",
        data=payload,
        verification_link=verification_link,
        cancel_url=cancel_url,
        email_title=subject,
        email_heading="Potwierdź adres e-mail do komunikacji w sprawie rezerwacji",
        **company_ctx,
    )

    text_body = (
        f"Dzień dobry {client_name},\n\n"
        f"Dziękujemy za dokonanie rezerwacji w {company_name}.\n\n"
        "Dane rezerwacji:\n"
        f"Klient: {payload.get('client_name') or '—'}\n"
        f"E-mail: {payload.get('client_email') or '—'}\n"
        f"Telefon: {payload.get('client_phone') or '—'}\n"
        f"Usługa: {payload.get('service_name') or '—'}\n"
        f"Osoba wykonująca usługę: {payload.get('employee_name') or '—'}\n"
        f"Data wizyty: {format_date_pl(payload.get('booking_date'))}\n"
        f"Godzina wizyty: {payload.get('booking_time') or '—'}\n\n"
        "W celu aktywacji komunikacji e-mail związanej z rezerwacją prosimy o potwierdzenie "
        "adresu e-mail, klikając w poniższy link:\n\n"
        f"{verification_link}\n\n"
        "Po potwierdzeniu adresu będziemy mogli przesyłać wiadomości dotyczące wizyty, "
        "w tym potwierdzenia, przypomnienia oraz informacje o ewentualnych zmianach."
    )

    if cancel_url:
        text_body += (
            "\n\n"
            "Jeżeli chcesz anulować tę rezerwację, możesz skorzystać z poniższego linku:\n\n"
            f"{cancel_url}"
        )

    text_body += (
        "\n\n"
        "Jeżeli ta wiadomość trafiła do Ciebie omyłkowo, wystarczy ją zignorować.\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(payload)}"
    )

    return send_email_message(client_email, subject, html_body, text_body)


def send_waitlist_verification_email(waitlist_id: int) -> bool:
    payload = get_waitlist_verification_payload(waitlist_id)
    if not payload:
        return False

    payload = row_to_dict(payload)

    client_id = payload.get("client_id")
    client_email = normalize_email(payload.get("client_email"))

    if not client_id or not client_email:
        return False

    token = assign_client_verification_token(client_id)
    if not token:
        return False

    verification_link = build_client_verification_link(token)
    company_name = get_company_display_name(payload.get("company_name"))
    team_signature = get_company_team_signature(payload.get("company_name"))
    client_name = (payload.get("client_name") or "Kliencie").strip()
    company_ctx = build_company_email_context(payload)

    subject = "Potwierdź adres e-mail do powiadomień z listy oczekujących"

    html_body = render_template(
        "emails/waitlist_verification.html",
        data=payload,
        verification_link=verification_link,
        email_title=subject,
        email_heading="Potwierdź adres e-mail do powiadomień z listy oczekujących",
        **company_ctx,
    )

    text_body = (
        f"Dzień dobry {client_name},\n\n"
        f"Potwierdzamy przyjęcie zgłoszenia do listy oczekujących w {company_name}.\n\n"
        "Dane zgłoszenia:\n"
        f"Klient: {payload.get('client_name') or '—'}\n"
        f"E-mail: {payload.get('client_email') or '—'}\n"
        f"Telefon: {payload.get('client_phone') or '—'}\n"
        f"Usługa: {payload.get('service_name') or '—'}\n"
        f"Osoba wykonująca usługę: {payload.get('employee_name') or '—'}\n"
        f"Preferowany zakres dat: {format_waitlist_date_range(payload.get('preferred_date_from'), payload.get('preferred_date_to'))}\n"
        f"Preferowany zakres godzin: {format_waitlist_time_range(payload.get('preferred_time_from'), payload.get('preferred_time_to'))}\n\n"
        "W celu aktywacji komunikacji e-mail związanej z tym zgłoszeniem prosimy o potwierdzenie "
        "adresu e-mail, klikając w poniższy link:\n\n"
        f"{verification_link}\n\n"
        "Po potwierdzeniu adresu będziemy mogli przesyłać wiadomości dotyczące listy oczekujących, "
        "w tym informacje o dostępności terminu oraz dalsze aktualizacje związane ze zgłoszeniem.\n\n"
        "Jeżeli ta wiadomość trafiła do Ciebie omyłkowo, wystarczy ją zignorować.\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(payload)}"
    )

    return send_email_message(client_email, subject, html_body, text_body)


# =========================================================
# INTERNAL NOTIFICATIONS - HTML/TEXT BUILDERS
# =========================================================

def build_email_detail_row(label: str, value: str) -> str:
    safe_label = escape(label)
    safe_value = escape(value or "—")

    return f"""
    <tr>
      <td style="padding:10px 18px 10px 0; vertical-align:top; font-weight:600; color:#241913; width:180px;">
        {safe_label}
      </td>
      <td style="padding:10px 0; vertical-align:top; color:#3b322d;">
        {safe_value}
      </td>
    </tr>
    """


def build_internal_email_wrapper(
    payload: dict,
    intro_text: str,
    recipient_label: str,
    rows_html: str
) -> str:
    payload = row_to_dict(payload)
    company_ctx = build_company_email_context(payload)

    safe_company_name = escape(company_ctx["company_name"])
    safe_intro_text = escape(intro_text)
    safe_recipient_label = escape(recipient_label)

    signature_html = (
        "Pozdrawiamy,<br>"
        f"<strong>{safe_company_name}</strong>"
    )

    footer_html = build_company_footer_html(payload)

    return f"""
    <div style="margin:0; padding:0; background:#f7f3ef;">
      <div style="max-width:680px; margin:0 auto; padding:32px 18px;">
        <div style="background:#ffffff; border:1px solid #e7ddd4; box-shadow:0 10px 30px rgba(30,22,17,0.06);">
          <div style="padding:28px 30px 18px 30px; border-bottom:1px solid #efe5dc; background:linear-gradient(180deg, #fcfaf7 0%, #ffffff 100%);">
            <div style="font-size:11px; letter-spacing:0.16em; text-transform:uppercase; color:#8a7668; margin-bottom:12px;">
              Alifio · Powiadomienie systemowe
            </div>
            <div style="font-family:Georgia, 'Times New Roman', serif; font-size:28px; line-height:1.25; color:#1f1712; margin:0 0 10px 0;">
              {safe_company_name}
            </div>
            <div style="width:240px; height:2px; background:#EAE0D5; margin:0 0 12px 0; font-size:0; line-height:0;">
              &#8203;
            </div>
            <div style="font-size:15px; line-height:1.8; color:#4a3f38; margin:0 0 8px 0;">
              {safe_intro_text}
            </div>
            <div style="display:inline-block; margin-top:10px; padding:8px 12px; border:1px solid #eadfd5; background:#faf6f1; font-size:13px; color:#5a4d44;">
              <strong>Odbiorca powiadomienia:</strong> {safe_recipient_label}
            </div>
          </div>

          <div style="padding:26px 30px 28px 30px;">
            <table cellpadding="0" cellspacing="0" border="0" width="100%" style="border-collapse:collapse; font-size:15px; line-height:1.85;">
              {rows_html}
            </table>
          </div>

          <div style="padding:18px 30px 24px 30px; border-top:1px solid #efe5dc; background:#fcfaf8; font-size:14px; line-height:1.8; color:#5d5149;">
            {signature_html}
            {footer_html}
          </div>
        </div>
      </div>
    </div>
    """


def build_booking_internal_email_html(payload, recipient_label: str) -> str:
    payload = row_to_dict(payload)

    rows_html = "".join([
        build_email_detail_row("Usługa:", payload.get("service_name") or "—"),
        build_email_detail_row("Osoba wykonująca usługę:", payload.get("employee_name") or "—"),
        build_email_detail_row("Klient:", payload.get("client_name") or "—"),
        build_email_detail_row("E-mail klienta:", payload.get("client_email") or "—"),
        build_email_detail_row("Telefon klienta:", payload.get("client_phone") or "—"),
        build_email_detail_row("Data wizyty:", format_date_pl(payload.get("booking_date"))),
        build_email_detail_row("Godzina wizyty:", payload.get("booking_time") or "—"),
        build_email_detail_row("Notatki:", (payload.get("notes") or "").strip() or "Brak dodatkowych notatek."),
        build_email_detail_row(
            "Zgoda na politykę prywatności:",
            format_consent_status(payload.get("privacy_consent"))
        ),
        build_email_detail_row(
            "Zgoda marketingowa:",
            format_consent_status(payload.get("marketing_consent"))
        ),
        build_email_detail_row(
            "Treść zgody na politykę prywatności:",
            "Potwierdzam, że zapoznałem(-am) się z Polityką Prywatności oraz rozumiem zasady przetwarzania danych osobowych w celu obsługi rezerwacji."
        ),
        build_email_detail_row(
            "Treść zgody marketingowej:",
            "Wyrażam zgodę na otrzymywanie informacji o ofertach, promocjach, nowościach i usługach drogą elektroniczną lub telefoniczną."
        ),
        build_email_detail_row(
            "Data udzielenia zgód:",
            payload.get("consents_created_at") or "—"
        ),
    ])

    return build_internal_email_wrapper(
        payload=payload,
        intro_text="W systemie została właśnie zapisana nowa rezerwacja. Poniżej znajdują się pełne szczegóły wizyty.",
        recipient_label=recipient_label,
        rows_html=rows_html,
    )


def build_booking_internal_email_text(payload, recipient_label: str) -> str:
    payload = row_to_dict(payload)

    company_name = get_company_display_name(payload.get("company_name"))
    team_signature = get_company_team_signature(payload.get("company_name"))

    return (
        f"Nowa rezerwacja w systemie {company_name}\n\n"
        f"Odbiorca powiadomienia: {recipient_label}\n\n"
        f"Usługa: {payload.get('service_name') or '—'}\n"
        f"Osoba wykonująca usługę: {payload.get('employee_name') or '—'}\n"
        f"Klient: {payload.get('client_name') or '—'}\n"
        f"E-mail klienta: {payload.get('client_email') or '—'}\n"
        f"Telefon klienta: {payload.get('client_phone') or '—'}\n"
        f"Data wizyty: {format_date_pl(payload.get('booking_date'))}\n"
        f"Godzina wizyty: {payload.get('booking_time') or '—'}\n"
        f"Notatki: {(payload.get('notes') or '').strip() or 'Brak dodatkowych notatek.'}\n"
        f"Zgoda na politykę prywatności: {format_consent_status(payload.get('privacy_consent'))}\n"
        f"Zgoda marketingowa: {format_consent_status(payload.get('marketing_consent'))}\n"
        "Treść zgody na politykę prywatności: Potwierdzam, że zapoznałem(-am) się z Polityką Prywatności oraz rozumiem zasady przetwarzania danych osobowych w celu obsługi rezerwacji.\n"
        "Treść zgody marketingowej: Wyrażam zgodę na otrzymywanie informacji o ofertach, promocjach, nowościach i usługach drogą elektroniczną lub telefoniczną.\n"
        f"Data udzielenia zgód: {payload.get('consents_created_at') or '—'}\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(payload)}"
    )


def build_waitlist_internal_email_html(payload, recipient_label: str) -> str:
    payload = row_to_dict(payload)

    rows_html = "".join([
        build_email_detail_row("Usługa:", payload.get("service_name") or "—"),
        build_email_detail_row("Osoba wykonująca usługę:", payload.get("employee_name") or "—"),
        build_email_detail_row("Klient:", payload.get("client_name") or "—"),
        build_email_detail_row("E-mail klienta:", payload.get("client_email") or "—"),
        build_email_detail_row("Telefon klienta:", payload.get("client_phone") or "—"),
        build_email_detail_row(
            "Preferowany zakres dat:",
            format_waitlist_date_range(payload.get("preferred_date_from"), payload.get("preferred_date_to"))
        ),
        build_email_detail_row(
            "Preferowany zakres godzin:",
            format_waitlist_time_range(payload.get("preferred_time_from"), payload.get("preferred_time_to"))
        ),
        build_email_detail_row("Notatki:", (payload.get("notes") or "").strip() or "Brak dodatkowych notatek."),
        build_email_detail_row(
            "Zgoda na politykę prywatności:",
            format_consent_status(payload.get("privacy_consent"))
        ),
        build_email_detail_row(
            "Zgoda marketingowa:",
            format_consent_status(payload.get("marketing_consent"))
        ),
        build_email_detail_row(
            "Treść zgody na politykę prywatności:",
            "Potwierdzam, że zapoznałem(-am) się z Polityką Prywatności oraz rozumiem zasady przetwarzania danych osobowych w celu obsługi zgłoszenia do listy oczekujących."
        ),
        build_email_detail_row(
            "Treść zgody marketingowej:",
            "Wyrażam zgodę na otrzymywanie informacji o ofertach, promocjach, nowościach i usługach drogą elektroniczną lub telefoniczną."
        ),
        build_email_detail_row(
            "Data udzielenia zgód:",
            payload.get("consents_created_at") or "—"
        ),
    ])

    return build_internal_email_wrapper(
        payload=payload,
        intro_text="W systemie pojawił się nowy wpis na liście oczekujących. Poniżej znajdują się szczegóły zgłoszenia.",
        recipient_label=recipient_label,
        rows_html=rows_html,
    )


def build_waitlist_internal_email_text(payload, recipient_label: str) -> str:
    payload = row_to_dict(payload)

    company_name = get_company_display_name(payload.get("company_name"))
    team_signature = get_company_team_signature(payload.get("company_name"))

    return (
        f"Nowy wpis na liście oczekujących w systemie {company_name}\n\n"
        f"Odbiorca powiadomienia: {recipient_label}\n\n"
        f"Usługa: {payload.get('service_name') or '—'}\n"
        f"Osoba wykonująca usługę: {payload.get('employee_name') or '—'}\n"
        f"Klient: {payload.get('client_name') or '—'}\n"
        f"E-mail klienta: {payload.get('client_email') or '—'}\n"
        f"Telefon klienta: {payload.get('client_phone') or '—'}\n"
        f"Preferowany zakres dat: {format_waitlist_date_range(payload.get('preferred_date_from'), payload.get('preferred_date_to'))}\n"
        f"Preferowany zakres godzin: {format_waitlist_time_range(payload.get('preferred_time_from'), payload.get('preferred_time_to'))}\n"
        f"Notatki: {(payload.get('notes') or '').strip() or 'Brak dodatkowych notatek.'}\n"
        f"Zgoda na politykę prywatności: {format_consent_status(payload.get('privacy_consent'))}\n"
        f"Zgoda marketingowa: {format_consent_status(payload.get('marketing_consent'))}\n"
        "Treść zgody na politykę prywatności: Potwierdzam, że zapoznałem(-am) się z Polityką Prywatności oraz rozumiem zasady przetwarzania danych osobowych w celu obsługi zgłoszenia do listy oczekujących.\n"
        "Treść zgody marketingowej: Wyrażam zgodę na otrzymywanie informacji o ofertach, promocjach, nowościach i usługach drogą elektroniczną lub telefoniczną.\n"
        f"Data udzielenia zgód: {payload.get('consents_created_at') or '—'}\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(payload)}"
    )


# =========================================================
# INTERNAL NOTIFICATIONS - SENDING
# =========================================================

def send_booking_internal_notifications(booking_id: int) -> dict:
    payload = get_booking_internal_notification_payload(booking_id)
    if not payload:
        return {"salon_sent": False, "employee_sent": False}

    payload = row_to_dict(payload)

    company_name = get_company_display_name(payload.get("company_name"))
    salon_email = normalize_email(payload.get("contact_email"))
    employee_email = normalize_email(payload.get("employee_email"))

    result = {
        "salon_sent": False,
        "employee_sent": False,
    }

    subject = f"Nowa rezerwacja — {company_name}"

    if salon_email:
        result["salon_sent"] = send_email_message(
            salon_email,
            subject,
            build_booking_internal_email_html(payload, "Firma"),
            build_booking_internal_email_text(payload, "Firma"),
        )

    if employee_email:
        result["employee_sent"] = send_email_message(
            employee_email,
            subject,
            build_booking_internal_email_html(payload, "Osoba wykonująca usługę"),
            build_booking_internal_email_text(payload, "Osoba wykonująca usługę"),
        )

    return result


def send_waitlist_internal_notifications(waitlist_id: int) -> dict:
    payload = get_waitlist_internal_notification_payload(waitlist_id)
    if not payload:
        return {"salon_sent": False, "employee_sent": False}

    payload = row_to_dict(payload)

    company_name = get_company_display_name(payload.get("company_name"))
    salon_email = normalize_email(payload.get("contact_email"))
    employee_email = normalize_email(payload.get("employee_email"))

    result = {
        "salon_sent": False,
        "employee_sent": False,
    }

    subject = f"Nowy wpis na liście oczekujących — {company_name}"

    if salon_email:
        result["salon_sent"] = send_email_message(
            salon_email,
            subject,
            build_waitlist_internal_email_html(payload, "Firma"),
            build_waitlist_internal_email_text(payload, "Firma"),
        )

    if employee_email:
        result["employee_sent"] = send_email_message(
            employee_email,
            subject,
            build_waitlist_internal_email_html(payload, "Osoba wykonująca usługę"),
            build_waitlist_internal_email_text(payload, "Osoba wykonująca usługę"),
        )

    return result


# =========================================================
# CANCELLATION EMAILS
# =========================================================

def send_booking_cancellation_confirmation_email(booking_data: dict) -> bool:
    booking_data = row_to_dict(booking_data)
    if not booking_data:
        return False

    client_email = normalize_email(booking_data.get("client_email"))
    if not client_email:
        return False

    company_name = get_company_display_name(booking_data.get("company_name"))
    team_signature = get_company_team_signature(booking_data.get("company_name"))
    client_name = (booking_data.get("client_name") or "Kliencie").strip()
    company_ctx = build_company_email_context(booking_data)

    subject = "Potwierdzenie anulowania rezerwacji"

    html_body = render_template(
        "emails/booking_cancel_confirmation.html",
        data=booking_data,
        email_title=subject,
        email_heading="Potwierdzenie anulowania rezerwacji",
        **company_ctx,
    )

    text_body = (
        f"Dzień dobry {client_name},\n\n"
        "Potwierdzamy, że Twoja rezerwacja została anulowana.\n\n"
        "Szczegóły anulowanej wizyty:\n"
        f"Klient: {(booking_data.get('client_name') or '—').strip()}\n"
        f"E-mail: {normalize_email(booking_data.get('client_email')) or '—'}\n"
        f"Telefon: {(booking_data.get('client_phone') or '—').strip()}\n"
        f"Usługa: {(booking_data.get('service_name') or '—').strip()}\n"
        f"Osoba wykonująca usługę: {(booking_data.get('employee_name') or '—').strip()}\n"
        f"Data wizyty: {format_date_pl(booking_data.get('booking_date'))}\n"
        f"Godzina wizyty: {(booking_data.get('booking_time') or '—').strip()}\n\n"
        "W razie potrzeby ponownej rezerwacji lub ustalenia nowego terminu "
        f"zapraszamy do kontaktu z {company_name}.\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(booking_data)}"
    )

    return send_email_message(
        to_email=client_email,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )


def send_booking_cancellation_internal_notifications(booking_data: dict) -> bool:
    booking_data = row_to_dict(booking_data)
    if not booking_data:
        return False

    company_name = get_company_display_name(booking_data.get("company_name"))
    team_signature = get_company_team_signature(booking_data.get("company_name"))

    service_name = (booking_data.get("service_name") or "—").strip()
    employee_name = (booking_data.get("employee_name") or "—").strip()
    client_name = (booking_data.get("client_name") or "—").strip()
    client_email = normalize_email(booking_data.get("client_email"))
    client_phone = (booking_data.get("client_phone") or "").strip()
    booking_date = format_date_pl(booking_data.get("booking_date"))
    booking_time = (booking_data.get("booking_time") or "—").strip()

    recipients = unique_email_list(
        booking_data.get("contact_email"),
        booking_data.get("employee_email"),
    )

    if not recipients:
        return False

    subject = f"Anulowano rezerwację — {client_name}"
    company_ctx = build_company_email_context(booking_data)

    html_body = render_template(
        "emails/booking_cancel_internal.html",
        data={
            "company_name": company_name,
            "company_address": company_ctx["company_address"],
            "contact_phone": company_ctx["contact_phone"],
            "contact_email": company_ctx["contact_email"],
            "website_url": company_ctx["website_url"],
            "service_name": service_name,
            "employee_name": employee_name,
            "client_name": client_name,
            "client_email": client_email,
            "client_phone": client_phone,
            "booking_date": booking_date,
            "booking_time": booking_time,
        },
        email_title=subject,
        email_heading="Rezerwacja została anulowana",
        **company_ctx,
    )

    text_body = (
        "W systemie odnotowano anulowanie rezerwacji.\n\n"
        "Szczegóły wizyty:\n"
        f"Klient: {client_name}\n"
        f"Usługa: {service_name}\n"
        f"Osoba wykonująca usługę: {employee_name}\n"
        f"Data wizyty: {booking_date}\n"
        f"Godzina wizyty: {booking_time}\n"
        f"E-mail klienta: {client_email or '—'}\n"
        f"Telefon klienta: {client_phone or '—'}\n\n"
        f"{team_signature}"
        f"{build_company_footer_text(booking_data)}"
    )

    return send_email_to_many(
        recipients=recipients,
        subject=subject,
        html_body=html_body,
        text_body=text_body,
    )


def send_booking_cancellation_notifications(booking_id: int) -> bool:
    payload = get_booking_cancellation_payload(booking_id)
    if not payload:
        return False

    payload = row_to_dict(payload)

    sent_any = False

    if send_booking_cancellation_internal_notifications(payload):
        sent_any = True

    if normalize_email(payload.get("client_email")):
        if send_booking_cancellation_confirmation_email(payload):
            sent_any = True

    return sent_any