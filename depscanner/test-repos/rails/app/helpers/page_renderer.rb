module PageRenderer
  def self.show(body)
    # XSS sink: `raw` bypasses Rails' default HTML escaping.
    raw(body)
  end
end
