<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Repository\UserRepository;

class UserController
{
    public function search(Request $request): Response
    {
        $name = $request->query->get('name');
        $rows = UserRepository::findByNameSafe($name);
        return new Response(json_encode($rows));
    }
}
