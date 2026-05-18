// Best-effort audit hook called before the render service — does not sanitize.

function auditRequest(req) {
  // In a real customer app this would write to an audit log.
  return req.headers && req.headers['x-request-id'];
}

module.exports = { auditRequest };
