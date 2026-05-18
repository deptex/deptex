require "grape"

# Grape API class declared but no endpoints (`get`/`post`) defined.
class API < Grape::API
  format :json
end
