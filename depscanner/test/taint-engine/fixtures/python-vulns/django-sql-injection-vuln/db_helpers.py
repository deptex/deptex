from django.db import connection


def run_query(sql):
    cursor = connection.cursor()
    cursor.execute(sql)
    return cursor.fetchone()
