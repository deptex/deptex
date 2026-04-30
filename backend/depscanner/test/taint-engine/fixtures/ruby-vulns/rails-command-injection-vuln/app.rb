# Rails controller — command injection via Kernel#system on a single string.
class DiagnosticsController < ApplicationController
  def ls
    target = params[:dir]
    # Single-string form — the shell parses `target`, so `;rm -rf /` works.
    system("ls #{target}")
    head :ok
  end

  def ping
    host = params[:host]
    # Backticks — same problem.
    output = `ping -c 1 #{host}`
    render plain: output
  end
end
