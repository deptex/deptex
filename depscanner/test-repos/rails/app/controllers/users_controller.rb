class UsersController < ApplicationController
  def search
    # REACHABLE: params[:name] concatenated into raw SQL via
    # ActiveRecord#find_by_sql — classic Rails SQLi shape.
    name = params[:name].to_s
    rows = User.find_by_sql("SELECT * FROM users WHERE name = '#{name}'")
    render json: rows
  end

  def show
    # UNREACHABLE: parameterised .find. ActiveRecord binds the id.
    render json: User.find(params[:id])
  end
end
