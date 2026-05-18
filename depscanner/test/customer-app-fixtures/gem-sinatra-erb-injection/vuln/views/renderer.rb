require 'erb'

class Renderer
  def self.render_user_template(source)
    # Sink: ERB.new on an attacker-controlled template source — server-side
    # template eval / XSS (registered as an xss sink in sinatra.yaml).
    template = ERB.new(source)
    template.result(binding)
  end
end
