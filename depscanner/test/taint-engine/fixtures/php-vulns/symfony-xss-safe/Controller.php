<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\View\BioRenderer;

class ProfileController
{
    public function show(Request $request): Response
    {
        $rawBio = $request->query->get('bio');
        $safeBio = htmlspecialchars($rawBio, ENT_QUOTES, 'UTF-8');
        $body = BioRenderer::render($safeBio);
        $resp = new Response();
        $resp->setContent($body);
        return $resp;
    }
}
