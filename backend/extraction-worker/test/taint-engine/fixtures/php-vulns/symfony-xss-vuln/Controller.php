<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\View\BioRenderer;

class ProfileController
{
    public function show(Request $request): Response
    {
        $bio = $request->query->get('bio');
        $body = BioRenderer::render($bio);
        $resp = new Response();
        $resp->setContent($body);
        return $resp;
    }
}
