Rails.application.routes.draw do
  post "/jobs", to: "jobs#create"
end
