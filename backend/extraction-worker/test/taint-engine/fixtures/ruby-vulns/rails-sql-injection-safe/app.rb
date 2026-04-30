# Rails controller — same flow as the vuln fixture but parameterized.
class UsersController < ApplicationController
  def search
    # Coerce to int via Integer() — sanitizes for sql_injection.
    id = Integer(params[:id])
    user = User.find(id)
    render json: user
  end

  def find_by_email
    # Coerce + bind — engine sees no raw SQL interpolation.
    email = params[:email].to_s
    rows = User.find_by(email: email.gsub(/[^a-z0-9@.\-_]/, ''))
    render json: rows
  end
end
