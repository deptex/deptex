# SSRF + open redirect + deserialization/code-injection + ReDoS sinks.
# One request input per action, flowing into a single dangerous sink, then
# returning a constant. Mirrors the proven ruby-vulns shapes.
class IntegrationsController < ApplicationController
  def fetch
    # REACHABLE: ssrf
    url = params[:url]
    body = Net::HTTP.get(URI(url))
    render plain: "fetched"
  end

  def proxy
    # REACHABLE: ssrf
    target = params[:target]
    resp = HTTParty.get(target)
    head :ok
  end

  def go
    # REACHABLE: open_redirect
    dest = params[:dest]
    redirect_to dest
  end

  def load_state
    # REACHABLE: deserialization
    blob = params[:state]
    data = Marshal.load(blob)
    head :ok
  end

  def run
    # REACHABLE: code_injection (eval)
    expr = params[:expr]
    eval(expr)
    head :ok
  end

  def filter
    # REACHABLE: redos
    pattern = params[:pattern]
    Regexp.new(pattern)
    head :ok
  end
end
