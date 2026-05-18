<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class EnvController extends AbstractController
{
    /**
     * CVE-2024-50340 — symfony/runtime 6.3.0 env override via query string.
     * The runtime resolves env vars from query string under specific configs.
     */
    #[Route('/env', name: 'env_show')]
    public function show(Request $request): Response
    {
        $name = $request->query->get('name');
        // Sink: getenv on attacker-controlled key (illustrative; real CVE
        // chains query into runtime env override).
        return new Response((string) getenv($name));
    }
}
