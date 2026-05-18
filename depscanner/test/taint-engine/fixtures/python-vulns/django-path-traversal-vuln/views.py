from django.http import FileResponse
from file_helpers import open_user_file


def download(request):
    filename = request.GET.get('file')
    fh = open_user_file(filename)
    return FileResponse(fh)
