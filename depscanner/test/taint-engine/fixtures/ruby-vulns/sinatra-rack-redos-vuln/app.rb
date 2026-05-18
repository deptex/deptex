# CVE-2024-25126-shaped — sinatra/rack < 3.0.9.1 path through Rack middleware
# where attacker-controlled Content-Type reaches Rack::MediaType.type, which
# uses a regex prone to catastrophic backtracking.
require 'rack/media_type'

class MediaTypeMiddleware
  def call(env)
    request = Rack::Request.new(env)
    content_type = request.get_header('CONTENT_TYPE')
    # ReDoS sink: regex over attacker-controlled string.
    Rack::MediaType.type(content_type)
    [200, {}, ['OK']]
  end
end
