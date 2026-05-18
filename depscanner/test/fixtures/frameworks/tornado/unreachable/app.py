import tornado.web


class HealthHandler(tornado.web.RequestHandler):
    def get(self):
        # No self.redirect anywhere — open-redirect sink unreachable.
        self.write({"ok": True})


app = tornado.web.Application([(r"/healthz", HealthHandler)])
