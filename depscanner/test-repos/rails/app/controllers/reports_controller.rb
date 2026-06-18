# SQL injection + command injection + path traversal sinks.
# Each action takes one request input and flows it into exactly ONE
# dangerous sink, then renders/returns a constant. Mirrors the proven
# ruby-vulns controller shapes (bare params[:x] -> local var -> sink).
class ReportsController < ApplicationController
  def search
    # REACHABLE: sql_injection
    q = params[:q]
    User.where("name = '#{q}'")
    head :ok
  end

  def order
    # REACHABLE: sql_injection
    sort = params[:sort]
    User.order("created_at #{sort}")
    head :ok
  end

  def execute
    # REACHABLE: sql_injection
    clause = params[:clause]
    ActiveRecord::Base.connection.execute("SELECT * FROM reports WHERE #{clause}")
    head :ok
  end

  def export
    # REACHABLE: command_injection
    filename = params[:filename]
    system("tar -czf /tmp/out.tgz #{filename}")
    head :ok
  end

  def ping
    # REACHABLE: command_injection
    host = params[:host]
    output = `ping -c 1 #{host}`
    render plain: "done"
  end

  def download
    # REACHABLE: path_traversal
    name = params[:name]
    contents = File.read("/var/reports/#{name}")
    render plain: "ok"
  end
end
