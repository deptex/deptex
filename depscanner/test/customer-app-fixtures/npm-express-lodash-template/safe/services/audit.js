// Audit hook — identical to vuln side. Not security-relevant; included to
// keep the file count parity between vuln/ and safe/ shapes.

function auditRequest(req) {
  return req.headers && req.headers['x-request-id'];
}

module.exports = { auditRequest };
