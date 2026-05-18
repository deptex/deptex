<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;

// Controller class declared but no #[Route] attribute, no method consumes
// $request->query->get(). The runtime env override path is unreachable.
class EnvController extends AbstractController
{
    public function unused(): void
    {
        // intentionally empty
    }
}
