class Audit
  def self.record(req)
    # Best-effort audit hook — does not sanitize.
    req.path
  end
end
