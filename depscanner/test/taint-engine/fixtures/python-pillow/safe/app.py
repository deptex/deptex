from flask import Flask, request
from PIL import ImageMath

app = Flask(__name__)


@app.route('/process')
def process_image():
    # Static expression — no taint reaches ImageMath.eval.
    return ImageMath.eval('1 + 1')
