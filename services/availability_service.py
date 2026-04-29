from datetime import datetime, date, time, timedelta
from services.db import get_connection


BOOKING_WINDOW_DAYS = 92


def parse_time(time_str: str) -> time:
    return datetime.strptime(time_str, "%H:%M").time()


def combine_date_and_time(target_date: date, time_str: str) -> datetime:
    return datetime.combine(target_date, parse_time(time_str))


def get_weekday_key(target_date: date) -> str:
    weekday_map = {
        0: "mon",
        1: "tue",
        2: "wed",
        3: "thu",
        4: "fri",
        5: "sat",
        6: "sun",
    }
    return weekday_map[target_date.weekday()]


def normalize_time_value(value) -> str:
    return (value or "").strip() if value else ""


def overlaps(start_a: datetime, end_a: datetime, start_b: datetime, end_b: datetime) -> bool:
    return start_a < end_b and end_a > start_b


def is_date_in_booking_window(target_date: date) -> bool:
    today = date.today()
    max_date = today + timedelta(days=BOOKING_WINDOW_DAYS)
    return today <= target_date <= max_date


def get_service_for_booking(cursor, service_id: int):
    cursor.execute(
        """
        SELECT id, name, duration_minutes, active
        FROM services
        WHERE id = ?
        """,
        (service_id,)
    )
    return cursor.fetchone()


def get_employee_for_booking(cursor, employee_id: int):
    cursor.execute(
        """
        SELECT id, full_name, active
        FROM employees
        WHERE id = ?
        """,
        (employee_id,)
    )
    return cursor.fetchone()


def is_employee_assigned_to_service(cursor, service_id: int, employee_id: int) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM service_employees
        WHERE service_id = ? AND employee_id = ?
        LIMIT 1
        """,
        (service_id, employee_id)
    )
    return cursor.fetchone() is not None


def get_slot_interval_minutes(cursor) -> int:
    cursor.execute(
        """
        SELECT slot_interval_minutes
        FROM business_settings
        WHERE id = 1
        """
    )
    row = cursor.fetchone()

    if not row:
        return 30

    interval = row["slot_interval_minutes"] if row["slot_interval_minutes"] else 30

    try:
        interval = int(interval)
    except (TypeError, ValueError):
        interval = 30

    if interval <= 0:
        interval = 30

    return interval


def is_company_closed(cursor, booking_date_str: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM closed_days
        WHERE closed_date = ?
        LIMIT 1
        """,
        (booking_date_str,)
    )
    return cursor.fetchone() is not None


def get_employee_schedule_for_day(cursor, employee_id: int, day_key: str):
    cursor.execute(
        """
        SELECT start_time, end_time, enabled
        FROM employee_work_schedule
        WHERE employee_id = ? AND day_key = ?
        LIMIT 1
        """,
        (employee_id, day_key)
    )
    return cursor.fetchone()


def is_employee_unavailable_on_date(cursor, employee_id: int, booking_date_str: str) -> bool:
    cursor.execute(
        """
        SELECT 1
        FROM employee_time_off
        WHERE employee_id = ?
          AND date(?) BETWEEN date(date_from) AND date(date_to)
        LIMIT 1
        """,
        (employee_id, booking_date_str)
    )
    return cursor.fetchone() is not None


def get_employee_schedule_exception_for_date(cursor, employee_id: int, booking_date_str: str):
    cursor.execute(
        """
        SELECT id, exception_date, is_day_off, start_time, end_time, note
        FROM employee_schedule_exceptions
        WHERE employee_id = ? AND exception_date = ?
        LIMIT 1
        """,
        (employee_id, booking_date_str)
    )
    return cursor.fetchone()


def resolve_employee_working_hours_for_date(cursor, employee_id: int, booking_date: date):
    booking_date_str = booking_date.isoformat()

    if is_company_closed(cursor, booking_date_str):
        return {
            "available": False,
            "reason": "closed_day",
            "start_time": None,
            "end_time": None,
        }

    if is_employee_unavailable_on_date(cursor, employee_id, booking_date_str):
        return {
            "available": False,
            "reason": "employee_time_off",
            "start_time": None,
            "end_time": None,
        }

    exception_data = get_employee_schedule_exception_for_date(cursor, employee_id, booking_date_str)
    if exception_data:
        if int(exception_data["is_day_off"]) == 1:
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

    day_key = get_weekday_key(booking_date)
    schedule = get_employee_schedule_for_day(cursor, employee_id, day_key)

    if not schedule:
        return {
            "available": False,
            "reason": "weekday_missing",
            "start_time": None,
            "end_time": None,
        }

    if int(schedule["enabled"]) != 1:
        return {
            "available": False,
            "reason": "weekday_off",
            "start_time": None,
            "end_time": None,
        }

    work_start_str = normalize_time_value(schedule["start_time"])
    work_end_str = normalize_time_value(schedule["end_time"])

    if not work_start_str or not work_end_str:
        return {
            "available": False,
            "reason": "missing_hours",
            "start_time": None,
            "end_time": None,
        }

    return {
        "available": True,
        "reason": "weekly_schedule",
        "start_time": work_start_str,
        "end_time": work_end_str,
    }


def get_existing_bookings_for_day(cursor, employee_id: int, booking_date_str: str):
    cursor.execute(
        """
        SELECT
            b.id,
            b.booking_time,
            b.status,
            s.duration_minutes
        FROM bookings b
        JOIN services s ON s.id = b.service_id
        WHERE b.employee_id = ?
          AND b.booking_date = ?
          AND b.status IN ('new', 'confirmed')
          AND COALESCE(b.archived, 0) = 0
        ORDER BY b.booking_time ASC
        """,
        (employee_id, booking_date_str)
    )
    return cursor.fetchall()


def build_busy_ranges(booking_date: date, existing_bookings):
    busy_ranges = []

    for booking in existing_bookings:
        booking_time_str = booking["booking_time"]
        duration_minutes = booking["duration_minutes"]

        if not booking_time_str or not duration_minutes:
            continue

        booking_start = combine_date_and_time(booking_date, booking_time_str)
        booking_end = booking_start + timedelta(minutes=int(duration_minutes))

        busy_ranges.append((booking_start, booking_end))

    return busy_ranges


def generate_time_slots(
    booking_date: date,
    work_start_str: str,
    work_end_str: str,
    service_duration_minutes: int,
    slot_interval_minutes: int,
    busy_ranges,
):
    slots = []

    work_start_dt = combine_date_and_time(booking_date, work_start_str)
    work_end_dt = combine_date_and_time(booking_date, work_end_str)

    if work_end_dt <= work_start_dt:
        return slots

    current_start = work_start_dt
    service_duration = timedelta(minutes=service_duration_minutes)
    slot_interval = timedelta(minutes=slot_interval_minutes)

    while current_start + service_duration <= work_end_dt:
        current_end = current_start + service_duration

        collision_found = False
        for busy_start, busy_end in busy_ranges:
            if overlaps(current_start, current_end, busy_start, busy_end):
                collision_found = True
                break

        if not collision_found:
            slots.append(current_start.strftime("%H:%M"))

        current_start += slot_interval

    return slots


def get_available_slots_for_day(service_id: int, employee_id: int, booking_date_str: str) -> list[str]:
    try:
        booking_date = datetime.strptime(booking_date_str, "%Y-%m-%d").date()
    except ValueError:
        return []

    if not is_date_in_booking_window(booking_date):
        return []

    conn = get_connection()
    cursor = conn.cursor()

    try:
        service = get_service_for_booking(cursor, service_id)
        if not service or int(service["active"]) != 1:
            return []

        employee = get_employee_for_booking(cursor, employee_id)
        if not employee or int(employee["active"]) != 1:
            return []

        if not is_employee_assigned_to_service(cursor, service_id, employee_id):
            return []

        day_resolution = resolve_employee_working_hours_for_date(cursor, employee_id, booking_date)

        if not day_resolution["available"]:
            return []

        work_start_str = day_resolution["start_time"]
        work_end_str = day_resolution["end_time"]

        if not work_start_str or not work_end_str:
            return []

        service_duration_minutes = int(service["duration_minutes"])
        slot_interval_minutes = get_slot_interval_minutes(cursor)

        existing_bookings = get_existing_bookings_for_day(cursor, employee_id, booking_date_str)
        busy_ranges = build_busy_ranges(booking_date, existing_bookings)

        return generate_time_slots(
            booking_date=booking_date,
            work_start_str=work_start_str,
            work_end_str=work_end_str,
            service_duration_minutes=service_duration_minutes,
            slot_interval_minutes=slot_interval_minutes,
            busy_ranges=busy_ranges,
        )
    finally:
        conn.close()