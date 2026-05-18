# Rails controller — accessor-parity SQL injection.
#
# Rails' StrongParameters / HashWithIndifferentAccess lets developers read
# the same value with either `params[:key]` (subscript form) or `params.key`
# (delegator dot form). Before the Ruby IR lowerer emitted a parity source
# step for 0-arg method calls, the tree-sitter `call` shape of `params.key`
# only matched call-shape framework specs (none for plain accessors), so
# the dot form was silently dropped while the bracket form flowed cleanly.
#
# This fixture exercises BOTH forms in the same handler to guard the parity.
class UsersController < ApplicationController
  def search
    # Bracket form — element_reference → source step. Always matched.
    q1 = params[:q]
    User.where("name = '#{q1}'")

    # Dot form — call(receiver=params, method=q, args=[]). Requires the
    # weak-source parity emission in ir.ts / handleCall to fire.
    q2 = params.q
    User.where("alias = '#{q2}'")
  end

  def headers
    # Chained dot-form on `request.headers` — accessor-shaped receiver
    # nested in another no-arg call. The lowerer's looksLikeAccessorReceiver
    # recurses through the inner `call` node to confirm the chain is an
    # accessor.
    h = request.headers.host
    User.where("host = '#{h}'")
  end
end
