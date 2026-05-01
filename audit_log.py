from models.db import get_connection


def add_audit_log(user_id, action_type, table_name, record_id, description):
    """
    Insert one audit log row only for real actions like INSERT / UPDATE / DELETE / LOGIN / LOGOUT.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            INSERT INTO audit_log
            (user_id, action_type, table_name, record_id, description)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (user_id, action_type, table_name, record_id, description)
        )
        connection.commit()
    except Exception as e:
        connection.rollback()
        print(f"Audit log insert failed: {e}")
    finally:
        cursor.close()
        connection.close()


def fetch_audit_logs():
    """
    Returns all audit logs in descending order.
    """
    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT log_id, user_id, action_type, table_name, record_id, action_timestamp, description
            FROM audit_log
            ORDER BY action_timestamp DESC, log_id DESC
            """
        )
        return cursor.fetchall()
    finally:
        cursor.close()
        connection.close()


def count_audit_logs():
    """
    Returns the total number of audit logs.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM audit_log")
        row = cursor.fetchone()
        return row[0] if row else 0
    finally:
        cursor.close()
        connection.close()