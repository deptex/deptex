require 'sinatra/base'
require_relative 'views/renderer'
require_relative 'views/audit'

class App < Sinatra::Base
  def search
    raw_name = params[:name]
    Audit.record(request)
    Renderer.render_greeting(raw_name)
  end
end
