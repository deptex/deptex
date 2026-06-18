<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class MatchController extends Controller
{
    public function filter(Request $request)
    {
        // REACHABLE: redos — user-supplied pattern into preg_match().
        $pattern = $request->input('pattern');
        $regex = '/' . $pattern . '/';
        $ok = preg_match($regex, 'subject');
        return response()->json(['ok' => true]);
    }
}
