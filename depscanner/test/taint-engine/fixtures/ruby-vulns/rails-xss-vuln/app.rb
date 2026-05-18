# Rails XSS via attacker-controlled string rendered through `raw` / html_safe.
# Cross-file: PostsController hands params[:comment] to PageRenderer.show,
# which calls raw() on it — bypassing the auto-escape.
require_relative 'page_renderer'

class PostsController < ApplicationController
  def show
    comment = params[:comment]
    @rendered = PageRenderer.show(comment)
    render html: @rendered
  end
end
