from datetime import datetime
from db import get_db_connection

def log_action(user_id, action, table_name=None, record_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO audit_log (user_id, action, table_name, record_id, timestamp)
        VALUES (%s, %s, %s, %s, %s)
    """

    cursor.execute(query, (
        user_id,
        action,
        table_name,
        record_id,
        datetime.now()
    ))

    conn.commit()
    cursor.close()
    conn.close()