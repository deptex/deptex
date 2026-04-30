require 'sinatra/base'
require 'cgi'
require_relative 'page_renderer'

class ProfileApp < Sinatra::Base
  get '/profile' do
    raw_bio = params[:bio]
    safe_bio = CGI.escapeHTML(raw_bio)
    PageRenderer.render_bio(safe_bio)
  end
end
