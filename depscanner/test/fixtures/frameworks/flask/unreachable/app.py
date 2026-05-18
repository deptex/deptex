from flask import Flask

# Flask is imported but the application has zero registered routes.
# CVE-2023-30861 requires a response path that can leak cookies — none exists.
app = Flask(__name__)
