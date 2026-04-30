require 'sinatra/base'
require_relative 'page_renderer'

class ProfileApp < Sinatra::Base
  get '/profile' do
    bio = params[:bio]
    PageRenderer.render_bio(bio)
  end
end
