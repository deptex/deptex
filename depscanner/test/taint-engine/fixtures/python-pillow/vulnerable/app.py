from flask import Flask, request
from PIL import ImageMath

app = Flask(__name__)


@app.route('/process')
def process_image():
    # CVE-2022-22817 shape — tainted expression flows into ImageMath.eval,
    # arbitrary code execution.
    expr = request.args.get('expr')
    return ImageMath.eval(expr)
