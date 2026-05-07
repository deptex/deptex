module PageRenderer
  def self.render_bio(escaped_bio)
    body = "<div class='bio'>#{escaped_bio}</div>"
    raw(body)
  end
end
