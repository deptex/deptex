module PageRenderer
  def self.render_bio(raw_bio)
    body = "<div class='bio'>#{raw_bio}</div>"
    raw(body)
  end
end
