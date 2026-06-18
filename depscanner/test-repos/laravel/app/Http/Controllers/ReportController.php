<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class ReportController extends Controller
{
    public function search(Request $request)
    {
        // REACHABLE: sql_injection — query string concatenated into raw SQL.
        $q = $request->input('q');
        $sql = "SELECT * FROM reports WHERE title = '" . $q . "'";
        $rows = DB::select($sql);
        return response()->json(['ok' => true]);
    }

    public function order(Request $request)
    {
        // REACHABLE: sql_injection — sort param into orderByRaw.
        $sort = $request->query('sort');
        $rows = DB::table('reports')->orderByRaw($sort)->get();
        return response()->json(['ok' => true]);
    }
}
