require "yaml"

# CVE-2022-32224 — Rails 6.1.4 unsafe YAML.load on attacker-controlled
# input enables deserialization-driven RCE.
class JobsController < ApplicationController
  def create
    payload = params[:data]
    # Sink: YAML.load on user-controlled string.
    job = YAML.load(payload)
    render json: job
  end
end
