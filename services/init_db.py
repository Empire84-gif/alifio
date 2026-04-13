from services.db import get_connection


def ensure_column(cursor, table_name, column_name, column_sql):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row["name"] for row in cursor.fetchall()]

    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA foreign_keys = ON")

    # =========================================================
    # SERVICES
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            service_group TEXT,
            duration_minutes INTEGER NOT NULL,
            price TEXT,
            active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # =========================================================
    # EMPLOYEES
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            role TEXT,
            email TEXT,
            photo_path TEXT,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =========================================================
    # SERVICE_EMPLOYEES
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS service_employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    """)

    # =========================================================
    # EMPLOYEE WORK SCHEDULE
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employee_work_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            day_key TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            start_time TEXT,
            end_time TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    """)

    # =========================================================
    # EMPLOYEE TIME OFF
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employee_time_off (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            date_from TEXT NOT NULL,
            date_to TEXT NOT NULL,
            note TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    """)

    # =========================================================
    # EMPLOYEE SCHEDULE EXCEPTIONS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employee_schedule_exceptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER NOT NULL,
            exception_date TEXT NOT NULL,
            is_day_off INTEGER NOT NULL DEFAULT 0,
            start_time TEXT,
            end_time TEXT,
            note TEXT,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
            UNIQUE(employee_id, exception_date)
        )
    """)

    # =========================================================
    # CLIENTS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            client_status TEXT DEFAULT 'standard',
            is_regular INTEGER NOT NULL DEFAULT 0,
            notes TEXT,
            preferred_employee_id INTEGER,
            privacy_consent INTEGER NOT NULL DEFAULT 0,
            marketing_consent INTEGER NOT NULL DEFAULT 0,
            privacy_consent_at TEXT,
            marketing_consent_at TEXT,
            consent_source TEXT,
            privacy_notice_confirmed INTEGER NOT NULL DEFAULT 0,
            privacy_notice_confirmed_at TEXT,
            privacy_notice_source TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (preferred_employee_id) REFERENCES employees(id) ON DELETE SET NULL
        )
    """)

    # =========================================================
    # BOOKINGS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            client_id INTEGER,
            client_name TEXT NOT NULL,
            client_email TEXT,
            client_phone TEXT NOT NULL,
            booking_date TEXT NOT NULL,
            booking_time TEXT NOT NULL,
            notes TEXT,
            status TEXT NOT NULL DEFAULT 'new',
            archived INTEGER NOT NULL DEFAULT 0,
            archived_at TEXT,
            archived_reason TEXT,
            privacy_consent INTEGER NOT NULL DEFAULT 0,
            marketing_consent INTEGER NOT NULL DEFAULT 0,
            consents_created_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE,
            FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL
        )
    """)

    # =========================================================
    # WAITLIST
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waitlist_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
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
            FOREIGN KEY (service_id) REFERENCES services(id) ON DELETE CASCADE,
            FOREIGN KEY (employee_id) REFERENCES employees(id) ON DELETE CASCADE
        )
    """)

    # =========================================================
    # BUSINESS SETTINGS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS business_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            company_name TEXT NOT NULL DEFAULT 'Booking System',
            company_address TEXT DEFAULT '',
            contact_phone TEXT DEFAULT '',
            primary_color TEXT NOT NULL DEFAULT '#1f3c88',
            contact_email TEXT,
            slot_interval_minutes INTEGER NOT NULL DEFAULT 30,
            logo_path TEXT,
            logo_width INTEGER NOT NULL DEFAULT 120,
            logo_height INTEGER NOT NULL DEFAULT 44,
            company_name_size INTEGER NOT NULL DEFAULT 22,
            logo_text_gap INTEGER NOT NULL DEFAULT 12,
            side_panels_enabled INTEGER NOT NULL DEFAULT 1,
            side_panels_autoplay INTEGER NOT NULL DEFAULT 1,
            side_panels_interval INTEGER NOT NULL DEFAULT 6
        )
    """)

    # =========================================================
    # BOOKING SIDE IMAGES
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS booking_side_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            side TEXT NOT NULL,
            image_path TEXT NOT NULL,
            sort_order INTEGER NOT NULL DEFAULT 1,
            is_active INTEGER NOT NULL DEFAULT 1
        )
    """)

    # =========================================================
    # CLOSED DAYS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS closed_days (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            closed_date TEXT NOT NULL UNIQUE,
            note TEXT
        )
    """)

    # =========================================================
    # ADMINS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =========================================================
    # PASSWORD RESET TOKENS
    # =========================================================
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expires_at TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (admin_id) REFERENCES admins(id) ON DELETE CASCADE
        )
    """)

    # =========================================================
    # ENSURE COLUMNS FOR OLDER DATABASES
    # =========================================================

    # employees
    ensure_column(cursor, "employees", "photo_path", "photo_path TEXT")

    # clients
    ensure_column(cursor, "clients", "client_status", "client_status TEXT DEFAULT 'standard'")
    ensure_column(cursor, "clients", "is_regular", "is_regular INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "clients", "notes", "notes TEXT")
    ensure_column(cursor, "clients", "preferred_employee_id", "preferred_employee_id INTEGER")
    ensure_column(cursor, "clients", "privacy_consent", "privacy_consent INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "clients", "marketing_consent", "marketing_consent INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "clients", "privacy_consent_at", "privacy_consent_at TEXT")
    ensure_column(cursor, "clients", "marketing_consent_at", "marketing_consent_at TEXT")
    ensure_column(cursor, "clients", "consent_source", "consent_source TEXT")
    ensure_column(cursor, "clients", "privacy_notice_confirmed", "privacy_notice_confirmed INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "clients", "privacy_notice_confirmed_at", "privacy_notice_confirmed_at TEXT")
    ensure_column(cursor, "clients", "privacy_notice_source", "privacy_notice_source TEXT")
    ensure_column(cursor, "clients", "created_at", "created_at TEXT DEFAULT CURRENT_TIMESTAMP")
    ensure_column(cursor, "clients", "updated_at", "updated_at TEXT DEFAULT CURRENT_TIMESTAMP")

    # bookings
    ensure_column(cursor, "bookings", "client_id", "client_id INTEGER")
    ensure_column(cursor, "bookings", "archived", "archived INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "bookings", "archived_at", "archived_at TEXT")
    ensure_column(cursor, "bookings", "archived_reason", "archived_reason TEXT")
    ensure_column(cursor, "bookings", "privacy_consent", "privacy_consent INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "bookings", "marketing_consent", "marketing_consent INTEGER NOT NULL DEFAULT 0")
    ensure_column(cursor, "bookings", "consents_created_at", "consents_created_at TEXT")

    # business_settings
    ensure_column(cursor, "business_settings", "company_address", "company_address TEXT DEFAULT ''")
    ensure_column(cursor, "business_settings", "contact_phone", "contact_phone TEXT DEFAULT ''")
    ensure_column(cursor, "business_settings", "side_panels_enabled", "side_panels_enabled INTEGER NOT NULL DEFAULT 1")
    ensure_column(cursor, "business_settings", "side_panels_autoplay", "side_panels_autoplay INTEGER NOT NULL DEFAULT 1")
    ensure_column(cursor, "business_settings", "side_panels_interval", "side_panels_interval INTEGER NOT NULL DEFAULT 6")

    # waitlist_entries
    ensure_column(cursor, "waitlist_entries", "matched_booking_date", "matched_booking_date TEXT")
    ensure_column(cursor, "waitlist_entries", "matched_booking_time", "matched_booking_time TEXT")
    ensure_column(cursor, "waitlist_entries", "created_at", "created_at TEXT DEFAULT CURRENT_TIMESTAMP")

    # booking_side_images
    ensure_column(cursor, "booking_side_images", "sort_order", "sort_order INTEGER NOT NULL DEFAULT 1")
    ensure_column(cursor, "booking_side_images", "is_active", "is_active INTEGER NOT NULL DEFAULT 1")

    # =========================================================
    # DEFAULT BUSINESS SETTINGS RECORD
    # =========================================================
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
            logo_text_gap,
            side_panels_enabled,
            side_panels_autoplay,
            side_panels_interval
        )
        VALUES (
            1,
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
    """)

    cursor.execute("""
        UPDATE business_settings
        SET
            company_address = COALESCE(company_address, ''),
            contact_phone = COALESCE(contact_phone, ''),
            side_panels_enabled = COALESCE(side_panels_enabled, 1),
            side_panels_autoplay = COALESCE(side_panels_autoplay, 1),
            side_panels_interval = COALESCE(side_panels_interval, 6)
        WHERE id = 1
    """)



if __name__ == "__main__":
    init_db()