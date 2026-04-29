def read_user_file(filename):
    with open(filename, 'rb') as fh:
        return fh.read()
