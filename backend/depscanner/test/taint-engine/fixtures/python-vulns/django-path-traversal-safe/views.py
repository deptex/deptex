from django.http import FileResponse
from file_helpers import open_user_file


def download(request):
    raw_name = request.GET.get('file')
    safe_name = _strip_path(raw_name)
    fh = open_user_file(safe_name)
    return FileResponse(fh)


def _strip_path(name):
    import os.path
    return os.path.basename(name)
