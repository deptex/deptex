require 'rack/utils'

# Same middleware shape but the regex pattern is a literal — no request
# data reaches Regexp.new.
class StatsMiddleware
  def call(env)
    _params = Rack::Utils.parse_query(env['QUERY_STRING'])
    pattern = '\\A\\d+\\z'
    Regexp.new(pattern)
    [200, {}, ['OK']]
  end
end
