from flask import Flask, request
import setuptools.package_index

app = Flask(__name__)


@app.route('/install')
def install():
    # CVE-2024-6345 shape — tainted URL flows into PackageIndex.download,
    # which fetches + extracts + invokes the downloaded distribution's
    # setup.py. Code-injection primitive.
    url = request.args.get('package_url')
    index = setuptools.package_index.PackageIndex()
    return index.download(url, '/tmp')
