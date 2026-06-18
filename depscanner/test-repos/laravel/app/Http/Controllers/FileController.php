<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class FileController extends Controller
{
    public function download(Request $request)
    {
        // REACHABLE: path_traversal — filename from query into file_get_contents().
        $name = $request->query('name');
        $path = '/var/data/' . $name;
        $contents = file_get_contents($path);
        return response()->json(['ok' => true]);
    }

    public function store(Request $request)
    {
        // REACHABLE: path_traversal — user-controlled path into file_put_contents().
        $dest = $request->input('dest');
        $target = '/var/uploads/' . $dest;
        file_put_contents($target, 'data');
        return response()->json(['ok' => true]);
    }
}
