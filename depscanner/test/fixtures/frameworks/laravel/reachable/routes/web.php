<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

// CVE-2021-43808 — Laravel 8.40.0 mail rendering XSS surface.
// Demonstrating reachability via raw HTML response interpolated with user input.
Route::get('/render', function (Request $request) {
    $name = $request->query('name');
    // Sink: raw HTML reflection without escaping.
    return response("<h1>Hello {$name}</h1>")->header('Content-Type', 'text/html');
});
