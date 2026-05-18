# Rails controller — same accessor forms as the vuln fixture but
# sanitized with `Integer(...)` before reaching the raw `where` sink.
# The weak source step emitted alongside the call step must NOT fight
# the call step's sanitizer match, or this fixture would regress to
# false-positive flows.
class UsersController < ApplicationController
  def search
    # Bracket form sanitized by Integer().
    id1 = Integer(params[:id])
    User.where("id = #{id1}")

    # Dot form sanitized by Integer().
    id2 = Integer(params.id)
    User.where("alt_id = #{id2}")
  end

  def headers
    # Dot-form on `request.headers` sanitized by `.to_i` (per the rails
    # spec, `*.to_i` is a sanitizer for SQL injection).
    port = request.headers.port.to_i
    User.where("port = #{port}")
  end
end
