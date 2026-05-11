module PageRenderer
  def self.show(body)
    # body is pre-escaped by the controller; raw() over an escaped value
    # is the conventional "I know what I'm doing" form.
    raw(body)
  end
end
