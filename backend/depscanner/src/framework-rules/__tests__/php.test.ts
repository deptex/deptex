import { phpModule } from '../../tree-sitter-extractor/languages/php';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('PHP framework detectors', () => {
  describe('laravel', () => {
    it('detects Route::get / Route::post in routes files', async () => {
      const file = await extractInline(
        phpModule,
        `<?php

use Illuminate\\Support\\Facades\\Route;

Route::get('/users', [UserController::class, 'index']);
Route::post('/users', 'UserController@store');
Route::delete('/users/{id}', [UserController::class, 'destroy']);
`,
        '/project/routes/web.php',
        [dep('laravel/framework', 'Illuminate')],
      );
      const eps = entryPointsFor(file, 'laravel');
      expect(eps.length).toBeGreaterThanOrEqual(3);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/users');
      expect(byMethod.get('POST')).toBe('/users');
      expect(byMethod.get('DELETE')).toBe('/users/{id}');
    });
  });

  describe('symfony', () => {
    it('detects #[Route] attributes on controller methods', async () => {
      const file = await extractInline(
        phpModule,
        `<?php

namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

class UserController
{
    #[Route('/users', methods: ['GET'])]
    public function list() {}

    #[Route('/users/{id}', methods: ['DELETE'])]
    public function delete(int $id) {}
}
`,
        '/project/src/Controller/UserController.php',
        [dep('symfony/routing', 'Symfony')],
      );
      const eps = entryPointsFor(file, 'symfony');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/users');
      expect(byMethod.get('DELETE')).toBe('/users/{id}');
    });
  });

  describe('slim', () => {
    it('detects $app->get() / $app->post()', async () => {
      const file = await extractInline(
        phpModule,
        `<?php

use Slim\\Factory\\AppFactory;

$app = AppFactory::create();

$app->get('/health', function ($request, $response) {
    $response->getBody()->write('ok');
    return $response;
});

$app->post('/login', function ($request, $response) {
    return $response;
});

$app->run();
`,
        '/project/public/index.php',
        [dep('slim/slim', 'Slim')],
      );
      const eps = entryPointsFor(file, 'slim');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/health');
      expect(byMethod.get('POST')).toBe('/login');
    });
  });
});
