<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class PingController extends Controller
{
    public function ping(Request $request)
    {
        // Tainted: host comes straight from the query string into system().
        $host = $request->input('host');
        $output = system('ping -c 1 ' . $host);
        return response()->json(['output' => $output]);
    }

    public function trace(Request $request)
    {
        // Tainted: shell_exec on concatenated user input.
        $target = $request->query('target');
        return shell_exec('traceroute ' . $target);
    }
}
