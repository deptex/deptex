def audit_request(req):
    # Best-effort audit hook. Not security-relevant; reads only the
    # request id header.
    return req.headers.get('X-Request-Id')
