import mysql.connector
from mysql.connector import Error
from flask import current_app


def get_connection():
    try:
        connection = mysql.connector.connect(
            host=current_app.config["MYSQL_HOST"],
            port=current_app.config["MYSQL_PORT"],
            user=current_app.config["MYSQL_USER"],
            password=current_app.config["MYSQL_PASSWORD"],
            database=current_app.config["MYSQL_DATABASE"]
        )
        return connection
    except Error as e:
        print("Database connection error:", e)
        return None