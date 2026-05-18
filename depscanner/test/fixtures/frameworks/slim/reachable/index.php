<?php

require __DIR__ . '/vendor/autoload.php';

use Slim\App;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

$app = new App();

// CVE-2019-12867 — slim/slim 3.12.1 header injection via withHeader on
// attacker-controlled value.
$app->get('/redirect', function (Request $req, Response $res) {
    $target = $req->getQueryParams()['u'] ?? '/';
    // Sink: header value from user input.
    return $res->withHeader('Location', $target)->withStatus(302);
});

$app->run();
