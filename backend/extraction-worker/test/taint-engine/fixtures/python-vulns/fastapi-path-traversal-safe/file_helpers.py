import os


def resolve_user_file(name):
    return os.path.join('/var/files', name)
