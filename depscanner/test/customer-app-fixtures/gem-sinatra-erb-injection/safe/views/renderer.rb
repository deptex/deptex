require 'erb'
require 'cgi'

# Patched: ERB source is a hard-coded literal compiled at class-load time.
# The user-supplied value is HTML-escaped via CGI.escapeHTML (a registered
# xss sanitizer in sinatra.yaml) before being interpolated as data.
class Renderer
  FIXED_TEMPLATE = ERB.new('<p>Hello, <%= @name %></p>')

  def self.render_greeting(name)
    safe_name = CGI.escapeHTML(name)
    @name = safe_name
    FIXED_TEMPLATE.result(binding)
  end
end
