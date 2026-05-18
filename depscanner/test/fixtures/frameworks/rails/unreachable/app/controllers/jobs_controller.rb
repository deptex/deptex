# Controller defined but never wired up in routes.rb. No YAML.load anywhere.
class JobsController < ApplicationController
  def index
    render json: { ok: true }
  end
end
