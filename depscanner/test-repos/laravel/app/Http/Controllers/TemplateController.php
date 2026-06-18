<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class TemplateController extends Controller
{
    public function compute(Request $request)
    {
        // REACHABLE: code_injection — expression from request into eval().
        $expr = $request->input('expr');
        $code = 'return ' . $expr . ';';
        eval($code);
        return response()->json(['ok' => true]);
    }

    public function restore(Request $request)
    {
        // REACHABLE: deserialization — cookie blob into unserialize().
        $blob = $request->cookie('state');
        $state = unserialize($blob);
        return response()->json(['ok' => true]);
    }
}
