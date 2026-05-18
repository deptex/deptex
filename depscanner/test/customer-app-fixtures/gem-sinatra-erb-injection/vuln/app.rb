require 'sinatra/base'
require_relative 'views/renderer'
require_relative 'views/audit'

class App < Sinatra::Base
  def search
    src = params[:tpl]
    Audit.record(request)
    Renderer.render_user_template(src)
  end
end
