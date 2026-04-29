<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class UserSearchController extends Controller
{
    public function search(Request $request)
    {
        // Safe: parameterized query — $q flows only into the bindings array.
        $q = $request->input('q');
        $rows = DB::select('SELECT * FROM users WHERE name = ?', [$q]);
        return response()->json($rows);
    }

    public function searchByName(Request $request)
    {
        // Safe: input numerically coerced via intval before use.
        $id = intval($request->input('id'));
        $sql = 'SELECT * FROM users WHERE id = ' . $id;
        $rows = DB::select($sql);
        return response()->json($rows);
    }
}
