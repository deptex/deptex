require_relative 'page_renderer'

# Same shape, but the comment is passed through ERB::Util.h before rendering,
# breaking the taint path to the XSS sink.
class PostsController < ApplicationController
  def show
    comment = params[:comment]
    escaped = ERB::Util.h(comment)
    @rendered = PageRenderer.show(escaped)
    render html: @rendered
  end
end
