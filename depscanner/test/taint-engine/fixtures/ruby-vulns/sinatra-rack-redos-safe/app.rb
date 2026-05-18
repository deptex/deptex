require 'rack/media_type'

# Same middleware shape, but the content type is hard-coded — no request
# data reaches the regex.
class MediaTypeMiddleware
  def call(env)
    content_type = 'text/plain'
    Rack::MediaType.type(content_type)
    [200, {}, ['OK']]
  end
end
