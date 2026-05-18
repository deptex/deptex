declare const followRedirects: any;

function handler() {
  // Hardened — explicit `beforeRedirect` strips sensitive headers when the
  // request follows a 30x to a different origin. Equivalent in effect to
  // upgrading past follow-redirects 1.15.6.
  followRedirects.http.request({
    hostname: 'example.com',
    path: '/final',
    headers: {
      'Proxy-Authorization': 'secret-token',
    },
    beforeRedirect: (opts: any, _res: any, req: any) => {
      if (new URL(opts.href).origin !== new URL(req.href).origin) {
        delete opts.headers['Proxy-Authorization'];
      }
    },
  }, (response: any) => {
    response.on('data', () => {});
  }).end();
}

handler();
