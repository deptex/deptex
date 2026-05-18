class Audit
  def self.record(req)
    req.path
  end
end
