<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class NetworkController extends Controller
{
    public function ping(Request $request)
    {
        // REACHABLE: command_injection — host from query string into system().
        $host = $request->input('host');
        $output = system('ping -c 1 ' . $host);
        return response()->json(['ok' => true]);
    }

    public function trace(Request $request)
    {
        // REACHABLE: command_injection — shell_exec on concatenated user input.
        $target = $request->query('target');
        $out = shell_exec('traceroute ' . $target);
        return response()->json(['ok' => true]);
    }
}
