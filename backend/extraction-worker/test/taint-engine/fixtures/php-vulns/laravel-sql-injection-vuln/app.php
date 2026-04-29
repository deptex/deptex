<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserSearchController extends Controller
{
    public function search(Request $request)
    {
        // Tainted: query string flows into a raw SQL string.
        $q = $request->input('q');
        $sql = "SELECT * FROM users WHERE name = '" . $q . "'";
        $rows = DB::select($sql);
        return response()->json($rows);
    }
}
