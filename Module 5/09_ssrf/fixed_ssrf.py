# fixed_ssrf.py
import requests, urllib.parse, socket, ipaddress
from flask import request, abort

ALLOWED_HOSTS = {"api.example.com", "static.example.org"}
ALLOWED_SCHEMES = {"https"}

def is_private(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        ipaddr = ipaddress.ip_address(ip)
        return ipaddr.is_private or ipaddr.is_loopback or ipaddr.is_link_local
    except Exception:
        return True

@app.route('/fetch')
def fetch():
    url = request.args.get('url', '')
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        abort(400)
    hostname = parsed.hostname
    if hostname not in ALLOWED_HOSTS:
        abort(400)
    if is_private(hostname):
        abort(400)
    # safe fetch: no redirects, short timeout
    resp = requests.get(url, timeout=5, allow_redirects=False)
    resp.raise_for_status()
    return resp.text
