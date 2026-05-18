declare const followRedirects: any;

function handler() {
  // CVE-2024-28849 shape — follow-redirects forwards sensitive headers
  // across redirect boundaries when the caller doesn't supply a
  // `beforeRedirect` callback. Without that callback the
  // `Proxy-Authorization` value here will be replayed verbatim against
  // whatever host the upstream returns in a 30x. The non-taint detector
  // regime fires sanitizer-absence directly on the inline options literal
  // — the `beforeRedirect` key is missing.
  followRedirects.http.request({
    hostname: 'example.com',
    path: '/final',
    headers: {
      'Proxy-Authorization': 'secret-token',
    },
  }, (response: any) => {
    response.on('data', () => {});
  }).end();
}

handler();
