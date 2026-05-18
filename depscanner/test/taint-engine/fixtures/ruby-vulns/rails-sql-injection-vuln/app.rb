# Rails controller — SQL injection via unparameterized `where`.
class UsersController < ApplicationController
  def search
    q = params[:q]
    # Raw SQL string interpolation — `q` lands directly in the WHERE clause.
    users = User.where("name = '#{q}'")
    render json: users
  end

  def find_by_email
    email = params[:email]
    # find_by_sql with attacker-controlled fragment.
    rows = User.find_by_sql("SELECT * FROM users WHERE email = '#{email}'")
    render json: rows
  end
end
