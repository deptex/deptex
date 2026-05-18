from django.db import connection


def get_user(request):
    user_id = request.GET.get('id')
    # Parameterized query — user input is bound, not concatenated.
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
    row = cursor.fetchone()
    return row


def get_user_int(request):
    raw = request.GET.get('id')
    # Numeric coercion makes the value safe for SQL identifiers.
    user_id = int(raw)
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
    return cursor.fetchone()
