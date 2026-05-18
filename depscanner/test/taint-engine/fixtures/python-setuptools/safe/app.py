from flask import Flask, request
import setuptools.package_index

app = Flask(__name__)


@app.route('/install')
def install():
    # Hard-coded URL — not tainted, no flow should be emitted.
    index = setuptools.package_index.PackageIndex()
    return index.download('https://pypi.org/simple/safe-package', '/tmp')
