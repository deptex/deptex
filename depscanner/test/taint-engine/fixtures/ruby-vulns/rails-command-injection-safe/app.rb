# Rails controller — same flow as the vuln fixture but escaped.
require 'shellwords'

class DiagnosticsController < ApplicationController
  def ls
    target = params[:dir]
    # Multi-arg form skips shell expansion AND we escape the operand.
    system("ls", Shellwords.escape(target))
    head :ok
  end

  def ping
    host = params[:host]
    # Multi-arg form — no shell, plus the operand is escaped.
    safe = Shellwords.escape(host)
    system("ping", "-c", "1", safe)
    head :ok
  end
end
