from django.db import connection


def get_user(request):
    user_id = request.GET.get('id')
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    row = cursor.fetchone()
    return row
