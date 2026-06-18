<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

class ProxyController extends Controller
{
    public function fetch(Request $request)
    {
        // REACHABLE: ssrf — user-supplied URL into Laravel Http::get().
        $url = $request->input('url');
        $response = Http::get($url);
        return response()->json(['ok' => true]);
    }

    public function callback(Request $request)
    {
        // REACHABLE: ssrf — user-supplied URL into curl_init().
        $endpoint = $request->query('endpoint');
        $ch = curl_init($endpoint);
        curl_exec($ch);
        return response()->json(['ok' => true]);
    }
}
