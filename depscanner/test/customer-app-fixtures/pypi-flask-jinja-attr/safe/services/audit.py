def audit_request(req):
    return req.headers.get('X-Request-Id')
