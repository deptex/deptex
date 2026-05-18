# Sidekiq Web / rack-attack-style Rack middleware mounted in a Rails app.
# Attacker controls QUERY_STRING; Rack::Utils.parse_query carries taint
# through to a downstream regex compile (model for CVE-2022-23837 family).
require 'rack/utils'

class StatsMiddleware
  def call(env)
    params = Rack::Utils.parse_query(env['QUERY_STRING'])
    pattern = params['filter']
    Regexp.new(pattern)
    [200, {}, ['OK']]
  end
end
