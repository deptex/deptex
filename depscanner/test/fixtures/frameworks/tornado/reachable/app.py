import tornado.web


class RedirectHandler(tornado.web.RequestHandler):
    """CVE-2023-28370 — Tornado <= 6.2 open redirect via Location header injection."""

    def get(self):
        target = self.get_argument("u")
        # Sink: redirect to user-controlled URL.
        self.redirect(target)


app = tornado.web.Application([(r"/redir", RedirectHandler)])
