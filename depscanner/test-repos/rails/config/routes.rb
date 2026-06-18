Rails.application.routes.draw do
  get "/users/search", to: "users#search"
  get "/users/:id",    to: "users#show"

  get  "/reports/search",   to: "reports#search"
  get  "/reports/order",    to: "reports#order"
  get  "/reports/execute",  to: "reports#execute"
  post "/reports/export",   to: "reports#export"
  get  "/reports/ping",     to: "reports#ping"
  get  "/reports/download", to: "reports#download"

  get  "/integrations/fetch",      to: "integrations#fetch"
  get  "/integrations/proxy",      to: "integrations#proxy"
  get  "/integrations/go",         to: "integrations#go"
  post "/integrations/load_state", to: "integrations#load_state"
  post "/integrations/run",        to: "integrations#run"
  get  "/integrations/filter",     to: "integrations#filter"

  get  "/posts/preview", to: "posts#preview"
end
