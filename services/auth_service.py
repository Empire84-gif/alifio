from werkzeug.security import generate_password_hash, check_password_hash

from services.db import get_connection

DEFAULT_SUPER_ADMIN_PERMISSIONS = {
    "can_manage_settings": 1,
    "can_manage_staff": 1,
    "can_manage_security": 1,
    "can_manage_services": 1,
    "can_manage_bookings": 1,
    "can_view_clients": 1,
    "can_edit_clients": 1,
    "can_view_reports": 1,
}

DEFAULT_CLIENT_ADMIN_PERMISSIONS = {
    "can_manage_settings": 1,
    "can_manage_staff": 1,
    "can_manage_security": 1,
    "can_manage_services": 1,
    "can_manage_bookings": 1,
    "can_view_clients": 1,
    "can_edit_clients": 1,
    "can_view_reports": 1,
}

DEFAULT_STAFF_PERMISSIONS = {
    "can_manage_settings": 0,
    "can_manage_staff": 0,
    "can_manage_security": 0,
    "can_manage_services": 0,
    "can_manage_bookings": 1,
    "can_view_clients": 1,
    "can_edit_clients": 0,
    "can_view_reports": 0,
}


def hash_password(password: str) -> str:
    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return check_password_hash(password_hash, password)


def get_user_by_email(email: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
        """,
        (email,)
    )
    user = cursor.fetchone()

    conn.close()
    return user


def get_user_by_id(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        LIMIT 1
        """,
        (user_id,)
    )
    user = cursor.fetchone()

    conn.close()
    return user


def update_user_password(user_id: int, new_password: str, must_change_password: int = 0):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET
            password_hash = ?,
            must_change_password = ?
        WHERE id = ?
        """,
        (
            hash_password(new_password),
            must_change_password,
            user_id
        )
    )

    conn.commit()
    conn.close()


def update_user_last_login(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE users
        SET last_login_at = CURRENT_TIMESTAMP
        WHERE id = ?
        """,
        (user_id,)
    )

    conn.commit()
    conn.close()


def create_user(
    business_id: int,
    email: str,
    password: str,
    full_name: str,
    role: str,
    employee_id: int | None = None,
    is_active: int = 1,
    must_change_password: int = 0,
    permissions: dict | None = None,
):
    email = (email or "").strip().lower()
    full_name = (full_name or "").strip()
    role = (role or "").strip()

    if not email:
        raise ValueError("Email is required.")

    if not full_name:
        raise ValueError("Full name is required.")

    if not password:
        raise ValueError("Password is required.")

    if role not in {"super_admin", "client_admin", "staff"}:
        raise ValueError("Invalid role.")

    if permissions is None:
        if role == "super_admin":
            permissions = DEFAULT_SUPER_ADMIN_PERMISSIONS.copy()
        elif role == "client_admin":
            permissions = DEFAULT_CLIENT_ADMIN_PERMISSIONS.copy()
        else:
            permissions = DEFAULT_STAFF_PERMISSIONS.copy()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO users (
                business_id,
                employee_id,
                email,
                password_hash,
                full_name,
                role,
                is_active,
                must_change_password,
                can_manage_settings,
                can_manage_staff,
                can_manage_security,
                can_manage_services,
                can_manage_bookings,
                can_view_clients,
                can_edit_clients,
                can_view_reports
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                business_id,
                employee_id,
                email,
                hash_password(password),
                full_name,
                role,
                is_active,
                must_change_password,
                permissions.get("can_manage_settings", 0),
                permissions.get("can_manage_staff", 0),
                permissions.get("can_manage_security", 0),
                permissions.get("can_manage_services", 0),
                permissions.get("can_manage_bookings", 0),
                permissions.get("can_view_clients", 0),
                permissions.get("can_edit_clients", 0),
                permissions.get("can_view_reports", 0),
            )
        )
        conn.commit()
        return cursor.lastrowid

    finally:
        conn.close()


def create_super_admin(
    email: str,
    password: str,
    full_name: str = "Super Admin",
    business_id: int = 1,
):
    existing_user = get_user_by_email(email)
    if existing_user:
        return None

    return create_user(
        business_id=business_id,
        email=email,
        password=password,
        full_name=full_name,
        role="super_admin",
        employee_id=None,
        is_active=1,
        must_change_password=0,
        permissions=DEFAULT_SUPER_ADMIN_PERMISSIONS.copy(),
    )


def create_client_admin(
    business_id: int,
    email: str,
    password: str,
    full_name: str,
):
    existing_user = get_user_by_email(email)
    if existing_user:
        return None

    return create_user(
        business_id=business_id,
        email=email,
        password=password,
        full_name=full_name,
        role="client_admin",
        employee_id=None,
        is_active=1,
        must_change_password=0,
        permissions=DEFAULT_CLIENT_ADMIN_PERMISSIONS.copy(),
    )


def create_staff_user(
    business_id: int,
    employee_id: int,
    email: str,
    password: str,
    full_name: str,
    must_change_password: int = 1,
):
    existing_user = get_user_by_email(email)
    if existing_user:
        return None

    return create_user(
        business_id=business_id,
        employee_id=employee_id,
        email=email,
        password=password,
        full_name=full_name,
        role="staff",
        is_active=1,
        must_change_password=must_change_password,
        permissions=DEFAULT_STAFF_PERMISSIONS.copy(),
    )


def user_has_permission(user, permission_name: str) -> bool:
    if not user:
        return False

    if user["role"] == "super_admin":
        return True

    return bool(user[permission_name]) if permission_name in user.keys() else False


# =========================================================
# LEGACY ADMINS - TEMPORARY COMPATIBILITY
# =========================================================

def get_admin_by_email(email: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admins WHERE email = ?", (email,))
    admin = cursor.fetchone()

    conn.close()
    return admin


def get_admin_by_id(admin_id: int):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
    admin = cursor.fetchone()

    conn.close()
    return admin


def update_admin_password(admin_id: int, new_password: str):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE admins
        SET password_hash = ?
        WHERE id = ?
        """,
        (
            hash_password(new_password),
            admin_id
        )
    )

    conn.commit()
    conn.close()