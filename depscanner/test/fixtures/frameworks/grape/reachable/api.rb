require "grape"

# CVE-2018-3769 — grape <= 1.0.2 reflected XSS in JSONP/format handling
# when user-controlled values land in the response without escaping.
class API < Grape::API
  format :json

  get "/echo" do
    # Sink: reflect user-controlled query param into response body.
    { msg: params[:msg] }
  end
end
