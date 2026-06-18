# Cross-file XSS: controller hands params[:comment] to PageRenderer.show,
# which calls raw() on it — bypassing the auto-escape. Mirrors the proven
# rails-xss-vuln reference shape.
require_relative "../helpers/page_renderer"

class PostsController < ApplicationController
  def preview
    # REACHABLE: xss
    comment = params[:comment]
    PageRenderer.show(comment)
    head :ok
  end
end
