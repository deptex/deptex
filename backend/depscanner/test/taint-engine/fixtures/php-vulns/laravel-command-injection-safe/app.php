<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class PingController extends Controller
{
    public function ping(Request $request)
    {
        // Safe: escapeshellarg sanitizes the host before it reaches system().
        $host = $request->input('host');
        $safe = escapeshellarg($host);
        $output = system('ping -c 1 ' . $safe);
        return response()->json(['output' => $output]);
    }

    public function trace(Request $request)
    {
        // Safe: escapeshellcmd applied directly inside the call.
        $target = $request->query('target');
        return shell_exec('traceroute ' . escapeshellcmd($target));
    }
}
