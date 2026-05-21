/**
 * v2.1d e2e fixture — minimal login app.
 *
 *   GET  /login        login form (email + password fields, submit button)
 *   POST /login        accepts hardcoded creds; sets a session cookie + redirects
 *   GET  /dashboard    auth-protected; the recorded login MUST reach this page
 *                      for the e2e harness to consider login successful
 *   GET  /             redirects to /login when unauthenticated
 *
 * Used by depscanner/test/e2e/dast-recorded.ts. The form fields are stable:
 *
 *   #email     — username input
 *   #pass      — password input
 *   button[type=submit] — submit button
 *
 * Logged-in indicator regex: "Welcome, alice"   (only present on /dashboard)
 * Logged-out indicator regex: "Sign in"          (only present on /login)
 *
 * Hard-coded credentials (not a secret — local fixture):
 *   email:    alice@example.com
 *   password: hunter2hunter2
 */

const express = require('express');

const app = express();
app.use(express.urlencoded({ extended: false }));

const USER = 'alice@example.com';
const PASS = 'hunter2hunter2';
const COOKIE = 'deptex-fixture-session=alice; Path=/; HttpOnly';

function isAuthed(req) {
  const cookie = req.headers.cookie ?? '';
  return cookie.includes('deptex-fixture-session=alice');
}

app.get('/', (req, res) => {
  if (isAuthed(req)) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html><head><title>Sign in — Deptex DAST fixture</title></head>
<body>
  <h1>Sign in</h1>
  <form method="POST" action="/login">
    <label>Email <input id="email" name="email" type="email" autocomplete="email" /></label>
    <label>Password <input id="pass" name="password" type="password" autocomplete="current-password" /></label>
    <button type="submit">Sign in</button>
  </form>
</body></html>`);
});

app.post('/login', (req, res) => {
  if (req.body.email === USER && req.body.password === PASS) {
    res.set('Set-Cookie', COOKIE);
    return res.redirect('/dashboard');
  }
  return res.status(401).redirect('/login');
});

app.get('/dashboard', (req, res) => {
  if (!isAuthed(req)) return res.redirect('/login');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html><head><title>Dashboard — Deptex DAST fixture</title></head>
<body>
  <h1>Welcome, alice</h1>
  <p>You are signed in.</p>
  <a href="/profile">Your profile</a>
</body></html>`);
});

app.get('/profile', (req, res) => {
  if (!isAuthed(req)) return res.redirect('/login');
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send('<h1>Welcome, alice</h1><p>Profile page (auth required).</p>');
});

const PORT = parseInt(process.env.PORT ?? '8080', 10);
const HOST = process.env.HOST ?? '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`[fixture] listening on http://${HOST}:${PORT}`);
});
