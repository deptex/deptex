require 'sinatra/base'
require_relative 'user_repo'

class SearchApp < Sinatra::Base
  get '/users' do
    q = params[:q]
    results = UserRepo.find_by_name(q)
    results.to_json
  end
end
