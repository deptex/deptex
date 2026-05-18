require "sinatra"
require "cgi"

get "/echo" do
  # REACHABLE: params[:msg] interpolated into ERB without escaping.
  erb "<div><%= params[:msg] %></div>"
end

get "/safe" do
  # UNREACHABLE: CGI escape on user input before interpolation.
  msg = CGI.escapeHTML(params[:msg] || "")
  erb "<div><%= msg %></div>"
end
