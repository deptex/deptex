<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class RedirectController extends Controller
{
    public function go(Request $request)
    {
        // REACHABLE: open_redirect — next param flows straight into redirect().
        $next = $request->query('next');
        return redirect($next);
    }

    public function away(Request $request)
    {
        // REACHABLE: open_redirect — external target into Redirect::away().
        $target = $request->input('target');
        return Redirect::away($target);
    }
}
