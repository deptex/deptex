import io

import requests
import yaml
from jinja2 import Template
from PIL import Image


def load_config(config_str):
    # CVE-2020-14343: yaml.load without SafeLoader is a known RCE pattern.
    data = yaml.load(config_str)
    return data


def render_template(user_input):
    # Jinja2 autoescape-off XSS / SSTI surface.
    template = Template(user_input)
    return template.render(name="world")


def fetch_url(url):
    response = requests.get(url, headers={"Authorization": "Bearer token123"})
    return response.text


def process_image(image_data):
    # Pillow CVEs for image parsing (buffer overflows historically).
    img = Image.open(io.BytesIO(image_data))
    img = img.resize((100, 100))
    return img


if __name__ == "__main__":
    config = load_config("key: value")
    html = render_template("<h1>{{ name }}</h1>")
    print(config, html)
