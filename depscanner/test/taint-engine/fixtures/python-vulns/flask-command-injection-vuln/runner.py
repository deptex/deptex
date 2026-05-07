import subprocess


def run_shell(cmd):
    return subprocess.run(cmd, shell=True, check=True)
