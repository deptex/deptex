<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\User;

class UserController extends Controller
{
    public function search(Request $request)
    {
        // REACHABLE: request input concatenated into raw SQL.
        $name = $request->input('name');
        return DB::select(DB::raw("SELECT * FROM users WHERE name = '$name'"));
    }

    public function show($id)
    {
        // UNREACHABLE: Eloquent find — parameterised.
        return User::find($id);
    }
}
