from services.db import get_connection


DEFAULT_BUSINESS_ID = 1
DEFAULT_BUSINESS_NAME = "Booking System"
DEFAULT_BUSINESS_SLUG = "booking-system"


def ensure_column(cursor, table_name, column_name, column_sql):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cursor.fetchall()]

    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def ensure_index(cursor, index_name, table_name, columns_sql, unique=False):
    unique_sql = "UNIQUE " if unique else ""
    cursor.execute(
        f"CREATE {unique_sql}INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns_sql})"
    )


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("PRAGMA foreign_keys = ON")

        # =========================================================
        # BUSINESSES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS businesses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                owner_email TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # =========================================================
        # USERS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER NOT NULL,
                employee_id INTEGER,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'staff',
                is_active INTEGER NOT NULL DEFAULT 1,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                can_manage_settings INTEGER NOT NULL DEFAULT 0,
                can_manage_staff INTEGER NOT NULL DEFAULT 0,
                can_manage_security INTEGER NOT NULL DEFAULT 0,
                can_manage_services INTEGER NOT NULL DEFAULT 0,
                can_manage_bookings INTEGER NOT NULL DEFAULT 0,
                can_view_clients INTEGER NOT NULL DEFAULT 0,
                can_edit_clients INTEGER NOT NULL DEFAULT 0,
                can_view_reports INTEGER NOT NULL DEFAULT 0,
                last_login_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # ACCOUNT ACTIVATION INVITES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS account_activation_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                business_name TEXT NOT NULL,
                business_slug TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'client_admin',
                is_used INTEGER NOT NULL DEFAULT 0,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_by_user_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by_user_id) REFERENCES users(id) ON DELETE SET NULL
            )
            """
        )

        # =========================================================
        # USER PASSWORD RESET TOKENS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # SERVICES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                name TEXT NOT NULL,
                service_group TEXT,
                duration_minutes INTEGER NOT NULL,
                price TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # EMPLOYEES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                full_name TEXT NOT NULL,
                role TEXT,
                email TEXT,
                photo_path TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # SERVICE_EMPLOYEES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS service_employees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                service_id INTEGER NOT NULL,
                employee_id INTEGER NOT NULL,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # EMPLOYEE WORK SCHEDULE
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS employee_work_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                employee_id INTEGER NOT NULL,
                day_key TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # EMPLOYEE TIME OFF
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS employee_time_off (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                employee_id INTEGER NOT NULL,
                type TEXT NOT NULL,
                date_from TEXT NOT NULL,
                date_to TEXT NOT NULL,
                note TEXT,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # EMPLOYEE SCHEDULE EXCEPTIONS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS employee_schedule_exceptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                employee_id INTEGER NOT NULL,
                exception_date TEXT NOT NULL,
                is_day_off INTEGER NOT NULL DEFAULT 0,
                start_time TEXT,
                end_time TEXT,
                note TEXT,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                UNIQUE(employee_id, exception_date)
            )
            """
        )

        # =========================================================
        # CLIENTS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                full_name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                email_verified INTEGER NOT NULL DEFAULT 0,
                email_verification_token TEXT,
                email_verification_sent_at TEXT,
                email_verified_at TEXT,
                client_status TEXT DEFAULT 'standard',
                is_regular INTEGER NOT NULL DEFAULT 0,
                blacklisted INTEGER NOT NULL DEFAULT 0,
                blacklist_reason TEXT,
                blacklisted_at TEXT,
                notes TEXT,
                preferred_employee_id INTEGER,
                privacy_consent INTEGER NOT NULL DEFAULT 0,
                marketing_consent INTEGER NOT NULL DEFAULT 0,
                privacy_consent_at TEXT,
                marketing_consent_at TEXT,
                email_notifications_enabled INTEGER NOT NULL DEFAULT 1,
                email_notifications_disabled_at TEXT,
                consent_source TEXT,
                privacy_notice_confirmed INTEGER NOT NULL DEFAULT 0,
                privacy_notice_confirmed_at TEXT,
                privacy_notice_source TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (preferred_employee_id) REFERENCES employees(id) ON DELETE SET NULL
            )
            """
        )

        # =========================================================
        # BOOKINGS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                service_id INTEGER NOT NULL,
                employee_id INTEGER NOT NULL,
                client_id INTEGER,
                client_name TEXT NOT NULL,
                client_email TEXT,
                client_phone TEXT NOT NULL,
                booking_date TEXT NOT NULL,
                booking_time TEXT NOT NULL,
                booking_type TEXT NOT NULL DEFAULT 'standard',
                custom_service_name TEXT,
                custom_service_price TEXT,
                custom_service_duration INTEGER,
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                archived INTEGER NOT NULL DEFAULT 0,
                archived_at TEXT,
                archived_reason TEXT,
                reminder_sent_at TEXT,
                privacy_consent INTEGER NOT NULL DEFAULT 0,
                marketing_consent INTEGER NOT NULL DEFAULT 0,
                consents_created_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
            )
            """
        )

        # =========================================================
        # WAITLIST
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS waitlist_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                service_id INTEGER NOT NULL,
                employee_id INTEGER NOT NULL,
                client_id INTEGER,
                client_name TEXT NOT NULL,
                client_email TEXT,
                client_phone TEXT,
                preferred_date_from TEXT,
                preferred_date_to TEXT,
                preferred_time_from TEXT,
                preferred_time_to TEXT,
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'waiting',
                matched_booking_date TEXT,
                matched_booking_time TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE,
                FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
                FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
            )
            """
        )

        # =========================================================
        # BUSINESS SETTINGS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS business_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                business_id INTEGER,
                company_name TEXT NOT NULL DEFAULT 'Booking System',
                company_address TEXT DEFAULT '',
                contact_phone TEXT DEFAULT '',
                primary_color TEXT NOT NULL DEFAULT '#1f3c88',
                contact_email TEXT,
                booking_page_url TEXT,
                slot_interval_minutes INTEGER NOT NULL DEFAULT 30,
                logo_path TEXT,
                logo_width INTEGER NOT NULL DEFAULT 120,
                logo_height INTEGER NOT NULL DEFAULT 44,
                company_name_size INTEGER NOT NULL DEFAULT 22,
                logo_text_gap INTEGER NOT NULL DEFAULT 12,
                side_panels_enabled INTEGER NOT NULL DEFAULT 1,
                side_panels_autoplay INTEGER NOT NULL DEFAULT 1,
                side_panels_interval INTEGER NOT NULL DEFAULT 6,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # BOOKING SIDE IMAGES
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS booking_side_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                side TEXT NOT NULL,
                image_path TEXT NOT NULL,
                sort_order INTEGER NOT NULL DEFAULT 1,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # CLOSED DAYS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS closed_days (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER,
                closed_date TEXT NOT NULL,
                note TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (business_id) REFERENCES businesses(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # LEGACY ADMINS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # =========================================================
        # LEGACY PASSWORD RESET TOKENS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # BOOKING CANCEL TOKENS
        # =========================================================
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS booking_cancel_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                booking_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TEXT,
                used_at TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (booking_id) REFERENCES bookings(id) ON DELETE CASCADE
            )
            """
        )

        # =========================================================
        # ENSURE COLUMNS FOR OLDER DATABASES
        # =========================================================

        # employees
        ensure_column(cursor, "employees", "business_id", "business_id INTEGER")
        ensure_column(cursor, "employees", "photo_path", "photo_path TEXT")
        ensure_column(cursor, "employees", "created_at", "created_at TEXT")

        # services
        ensure_column(cursor, "services", "business_id", "business_id INTEGER")
        ensure_column(cursor, "services", "created_at", "created_at TEXT")

        # service_employees
        ensure_column(cursor, "service_employees", "business_id", "business_id INTEGER")

        # employee_work_schedule
        ensure_column(cursor, "employee_work_schedule", "business_id", "business_id INTEGER")

        # employee_time_off
        ensure_column(cursor, "employee_time_off", "business_id", "business_id INTEGER")

        # employee_schedule_exceptions
        ensure_column(cursor, "employee_schedule_exceptions", "business_id", "business_id INTEGER")

        # clients
        ensure_column(cursor, "clients", "business_id", "business_id INTEGER")
        ensure_column(cursor, "clients", "email_verified", "email_verified INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "email_verification_token", "email_verification_token TEXT")
        ensure_column(cursor, "clients", "email_verification_sent_at", "email_verification_sent_at TEXT")
        ensure_column(cursor, "clients", "email_verified_at", "email_verified_at TEXT")
        ensure_column(cursor, "clients", "client_status", "client_status TEXT DEFAULT 'standard'")
        ensure_column(cursor, "clients", "is_regular", "is_regular INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "blacklisted", "blacklisted INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "blacklist_reason", "blacklist_reason TEXT")
        ensure_column(cursor, "clients", "blacklisted_at", "blacklisted_at TEXT")
        ensure_column(cursor, "clients", "notes", "notes TEXT")
        ensure_column(cursor, "clients", "preferred_employee_id", "preferred_employee_id INTEGER")
        ensure_column(cursor, "clients", "privacy_consent", "privacy_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "marketing_consent", "marketing_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "privacy_consent_at", "privacy_consent_at TEXT")
        ensure_column(cursor, "clients", "marketing_consent_at", "marketing_consent_at TEXT")
        ensure_column(cursor, "clients", "email_notifications_enabled", "email_notifications_enabled INTEGER NOT NULL DEFAULT 1")
        ensure_column(cursor, "clients", "email_notifications_disabled_at", "email_notifications_disabled_at TEXT")
        ensure_column(cursor, "clients", "consent_source", "consent_source TEXT")
        ensure_column(cursor, "clients", "privacy_notice_confirmed", "privacy_notice_confirmed INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "clients", "privacy_notice_confirmed_at", "privacy_notice_confirmed_at TEXT")
        ensure_column(cursor, "clients", "privacy_notice_source", "privacy_notice_source TEXT")
        ensure_column(cursor, "clients", "created_at", "created_at TEXT")
        ensure_column(cursor, "clients", "updated_at", "updated_at TEXT")

        # bookings
        ensure_column(cursor, "bookings", "business_id", "business_id INTEGER")
        ensure_column(cursor, "bookings", "client_id", "client_id INTEGER")
        ensure_column(cursor, "bookings", "booking_type", "booking_type TEXT NOT NULL DEFAULT 'standard'")
        ensure_column(cursor, "bookings", "custom_service_name", "custom_service_name TEXT")
        ensure_column(cursor, "bookings", "custom_service_price", "custom_service_price TEXT")
        ensure_column(cursor, "bookings", "custom_service_duration", "custom_service_duration INTEGER")
        ensure_column(cursor, "bookings", "archived", "archived INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "bookings", "archived_at", "archived_at TEXT")
        ensure_column(cursor, "bookings", "archived_reason", "archived_reason TEXT")
        ensure_column(cursor, "bookings", "reminder_sent_at", "reminder_sent_at TEXT")
        ensure_column(cursor, "bookings", "privacy_consent", "privacy_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "bookings", "marketing_consent", "marketing_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "bookings", "consents_created_at", "consents_created_at TEXT")
        ensure_column(cursor, "bookings", "created_at", "created_at TEXT")

        # waitlist_entries
        ensure_column(cursor, "waitlist_entries", "business_id", "business_id INTEGER")
        ensure_column(cursor, "waitlist_entries", "client_id", "client_id INTEGER")
        ensure_column(cursor, "waitlist_entries", "matched_booking_date", "matched_booking_date TEXT")
        ensure_column(cursor, "waitlist_entries", "matched_booking_time", "matched_booking_time TEXT")
        ensure_column(cursor, "waitlist_entries", "created_at", "created_at TEXT")
        ensure_column(cursor, "waitlist_entries", "privacy_consent", "privacy_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "waitlist_entries", "marketing_consent", "marketing_consent INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "waitlist_entries", "consents_created_at", "consents_created_at TEXT")
        ensure_column(cursor, "waitlist_entries", "cancel_token", "cancel_token TEXT")
        ensure_column(cursor, "waitlist_entries", "cancel_token_used", "cancel_token_used INTEGER NOT NULL DEFAULT 0")
        ensure_column(cursor, "waitlist_entries", "cancelled_at", "cancelled_at TEXT")

        # business_settings
        ensure_column(cursor, "business_settings", "business_id", "business_id INTEGER")
        ensure_column(cursor, "business_settings", "company_address", "company_address TEXT DEFAULT ''")
        ensure_column(cursor, "business_settings", "contact_phone", "contact_phone TEXT DEFAULT ''")
        ensure_column(cursor, "business_settings", "privacy_policy_url", "privacy_policy_url TEXT")
        ensure_column(cursor, "business_settings", "terms_url", "terms_url TEXT")
        ensure_column(cursor, "business_settings", "booking_page_url", "booking_page_url TEXT")
        ensure_column(cursor, "business_settings", "side_panels_enabled", "side_panels_enabled INTEGER NOT NULL DEFAULT 1")
        ensure_column(cursor, "business_settings", "side_panels_autoplay", "side_panels_autoplay INTEGER NOT NULL DEFAULT 1")
        ensure_column(cursor, "business_settings", "side_panels_interval", "side_panels_interval INTEGER NOT NULL DEFAULT 6")
        ensure_column(cursor, "business_settings", "created_at", "created_at TEXT")

        # booking_side_images
        ensure_column(cursor, "booking_side_images", "business_id", "business_id INTEGER")
        ensure_column(cursor, "booking_side_images", "sort_order", "sort_order INTEGER NOT NULL DEFAULT 1")
        ensure_column(cursor, "booking_side_images", "is_active", "is_active INTEGER NOT NULL DEFAULT 1")
        ensure_column(cursor, "booking_side_images", "created_at", "created_at TEXT")

        # closed_days
        ensure_column(cursor, "closed_days", "business_id", "business_id INTEGER")
        ensure_column(cursor, "closed_days", "created_at", "created_at TEXT")

        # =========================================================
        # INDEXES
        # =========================================================
        ensure_index(cursor, "idx_users_business_id", "users", "business_id")
        ensure_index(cursor, "idx_users_employee_id", "users", "employee_id")
        ensure_index(cursor, "idx_users_role", "users", "role")
        ensure_index(cursor, "idx_activation_invites_email", "account_activation_invites", "email")
        ensure_index(cursor, "idx_user_reset_tokens_user_id", "user_password_reset_tokens", "user_id")

        ensure_index(cursor, "idx_services_business_id", "services", "business_id")
        ensure_index(cursor, "idx_employees_business_id", "employees", "business_id")
        ensure_index(cursor, "idx_service_employees_business_id", "service_employees", "business_id")
        ensure_index(cursor, "idx_employee_work_schedule_business_id", "employee_work_schedule", "business_id")
        ensure_index(cursor, "idx_employee_time_off_business_id", "employee_time_off", "business_id")
        ensure_index(cursor, "idx_employee_schedule_exceptions_business_id", "employee_schedule_exceptions", "business_id")
        ensure_index(cursor, "idx_clients_business_id", "clients", "business_id")
        ensure_index(cursor, "idx_bookings_business_id", "bookings", "business_id")
        ensure_index(cursor, "idx_bookings_custom_lookup", "bookings", "business_id, booking_type, booking_date")
        ensure_index(cursor, "idx_waitlist_entries_business_id", "waitlist_entries", "business_id")
        ensure_index(cursor, "idx_business_settings_business_id", "business_settings", "business_id")
        ensure_index(cursor, "idx_booking_side_images_business_id", "booking_side_images", "business_id")
        ensure_index(cursor, "idx_closed_days_business_id", "closed_days", "business_id")
        ensure_index(cursor, "idx_booking_cancel_tokens_booking_id", "booking_cancel_tokens", "booking_id")

        ensure_index(
            cursor,
            "idx_bookings_reminder_lookup",
            "bookings",
            "booking_date, archived, reminder_sent_at, status",
        )

        ensure_index(
            cursor,
            "idx_closed_days_business_date",
            "closed_days",
            "business_id, closed_date",
            unique=True,
        )

        # =========================================================
        # DEFAULT BUSINESS
        # =========================================================
        cursor.execute(
            """
            INSERT OR IGNORE INTO businesses (
                id,
                name,
                slug,
                owner_email,
                is_active
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                DEFAULT_BUSINESS_ID,
                DEFAULT_BUSINESS_NAME,
                DEFAULT_BUSINESS_SLUG,
                None,
            ),
        )

        # =========================================================
        # DEFAULT BUSINESS SETTINGS RECORD
        # =========================================================
        cursor.execute(
            """
            INSERT OR IGNORE INTO business_settings (
                id,
                business_id,
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
                side_panels_enabled,
                side_panels_autoplay,
                side_panels_interval
            )
            VALUES (
                1,
                ?,
                'Booking System',
                '',
                '',
                '#1f3c88',
                'kontakt@example.com',
                30,
                NULL,
                120,
                44,
                22,
                12,
                1,
                1,
                6
            )
            """,
            (DEFAULT_BUSINESS_ID,),
        )

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS marketing_templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                business_id INTEGER NOT NULL,
                template_key TEXT NOT NULL,
                subject TEXT,
                preview_text TEXT,
                body TEXT,
                cta_text TEXT,
                image_path TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(business_id, template_key)
            )
            """)
        
        ensure_column(cursor, "marketing_templates", "template_name", "template_name TEXT")

        ensure_column(cursor, "marketing_templates", "audience_type", "audience_type TEXT")
        ensure_column(cursor, "marketing_templates", "discount_value", "discount_value TEXT")
        ensure_column(cursor, "marketing_templates", "service_name_value", "service_name_value TEXT")
        ensure_column(cursor, "marketing_templates", "offer_deadline", "offer_deadline TEXT")
        ensure_column(cursor, "marketing_templates", "cta_url", "cta_url TEXT")

        ensure_index(cursor, "idx_marketing_templates_business", "marketing_templates", "business_id")

        # =========================================================
        # BACKFILL EXISTING DATA TO DEFAULT BUSINESS
        # =========================================================
        tables_to_backfill = [
            "services",
            "employees",
            "service_employees",
            "employee_work_schedule",
            "employee_time_off",
            "employee_schedule_exceptions",
            "clients",
            "bookings",
            "waitlist_entries",
            "booking_side_images",
            "closed_days",
        ]

        for table_name in tables_to_backfill:
            cursor.execute(
                f"""
                UPDATE {table_name}
                SET business_id = ?
                WHERE business_id IS NULL
                """,
                (DEFAULT_BUSINESS_ID,),
            )

        cursor.execute(
            """
            UPDATE business_settings
            SET
                business_id = COALESCE(business_id, ?),
                company_address = COALESCE(company_address, ''),
                contact_phone = COALESCE(contact_phone, ''),
                side_panels_enabled = COALESCE(side_panels_enabled, 1),
                side_panels_autoplay = COALESCE(side_panels_autoplay, 1),
                side_panels_interval = COALESCE(side_panels_interval, 6)
            WHERE id = 1
            """,
            (DEFAULT_BUSINESS_ID,),
        )

        # =========================================================
        # BACKFILL CREATED_AT / UPDATED_AT
        # =========================================================
        cursor.execute("UPDATE services SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
        cursor.execute("UPDATE employees SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")

        cursor.execute(
            """
            UPDATE clients
            SET
                created_at = COALESCE(created_at, CURRENT_TIMESTAMP),
                updated_at = COALESCE(updated_at, CURRENT_TIMESTAMP),
                blacklisted = COALESCE(blacklisted, 0)
            """
        )

        cursor.execute("UPDATE bookings SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
        cursor.execute("UPDATE waitlist_entries SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")

        cursor.execute(
            """
            UPDATE business_settings
            SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)
            WHERE id = 1
            """
        )

        cursor.execute("UPDATE booking_side_images SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")
        cursor.execute("UPDATE closed_days SET created_at = COALESCE(created_at, CURRENT_TIMESTAMP)")


        ensure_index(
            cursor,
                "idx_marketing_templates_business",
                "marketing_templates",
                "business_id"
            )



        conn.commit()
        print("Baza danych została zainicjalizowana pomyślnie.")

    finally:
        conn.close()


if __name__ == "__main__":
    init_db()