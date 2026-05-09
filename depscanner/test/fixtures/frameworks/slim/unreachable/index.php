<?php

require __DIR__ . '/vendor/autoload.php';

use Slim\App;

// Slim app instantiated, but no routes registered and no $app->run() either.
// Header-injection sink unreachable.
$app = new App();
unset($app);
