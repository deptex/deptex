from db_helpers import run_query


def list_users(request):
    name = request.GET.get('name')
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return run_query(sql)
