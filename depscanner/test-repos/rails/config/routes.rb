Rails.application.routes.draw do
  get "/users/search", to: "users#search"
  get "/users/:id",    to: "users#show"
end
