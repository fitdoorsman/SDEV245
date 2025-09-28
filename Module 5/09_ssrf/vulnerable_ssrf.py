# vulnerable_ssrf.py
import requests
from flask import request

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    # Directly fetching user-supplied URL (SSRF risk)
    r = requests.get(url, timeout=5)
    return r.text
