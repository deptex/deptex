require "rails/all"
Bundler.require(*Rails.groups)

module DeptexDogfoodRails
  class Application < Rails::Application
    config.load_defaults 6.0
    config.api_only = true
  end
end
