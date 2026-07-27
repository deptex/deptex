/**
 * Unit tests for the Symfony framework detector's legacy Doctrine-style
 * docblock `@Route` annotation path (Symfony ≤5 / PHP 7.x), alongside the
 * native PHP-8 `#[Route]` attribute path. Runs the real PHP language module +
 * detector over inline source via `extractInline` — no workspace staging.
 *
 * Run: npx tsx test/framework-detector-symfony.test.ts
 */

import { phpModule } from '../src/tree-sitter-extractor/languages/php';
import { dep, entryPointsFor, extractInline } from '../src/framework-rules/test-helpers';
import type { EntryPoint } from '../src/framework-rules/types';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

async function detect(source: string): Promise<EntryPoint[]> {
  const file = await extractInline(phpModule, source, '/tmp/Controller.php', [
    dep('symfony/framework-bundle'),
    dep('symfony/routing'),
  ]);
  return entryPointsFor(file, 'symfony');
}

/** All (handler, method, path) tuples — order-independent membership checks. */
function has(eps: EntryPoint[], handler: string, method: string | null, path: string): boolean {
  return eps.some((e) => e.handlerName === handler && e.httpMethod === method && e.routePattern === path);
}

async function main(): Promise<void> {
  // ---------------------------------------------------------------------------
  // 1. Legacy docblock @Route: class-level prefix + method paths + methods,
  //    route params preserved, multiple @Route lines on one method, and
  //    non-@Route docblocks ignored.
  // ---------------------------------------------------------------------------
  console.log('legacy @Route docblock annotations (symfony/demo shape):');
  {
    const src = `<?php
namespace App\\Controller;

use Symfony\\Bundle\\FrameworkBundle\\Controller\\AbstractController;
use Symfony\\Component\\HttpFoundation\\Request;
use Symfony\\Component\\Routing\\Annotation\\Route;

/**
 * Controller used to manage blog contents.
 *
 * @Route("/blog")
 */
class BlogController extends AbstractController
{
    /**
     * @Route("/", methods={"GET"}, name="blog_index")
     * @Route("/rss.xml", methods={"GET"}, name="blog_rss")
     * @Route("/page/{page<[1-9]\\d*>}", methods={"GET"}, name="blog_index_paginated")
     */
    public function index(Request $request): Response
    {
        return $this->render('blog/index.html.twig');
    }

    /**
     * @Route("/posts/{slug}", methods={"GET"}, name="blog_post")
     */
    public function postShow(Post $post): Response
    {
        return $this->render('blog/post_show.html.twig');
    }

    /**
     * @Route("/comment/{postSlug}/new", methods={"POST"}, name="comment_new")
     * @IsGranted("IS_AUTHENTICATED_FULLY")
     * @ParamConverter("post", options={"mapping": {"postSlug": "slug"}})
     */
    public function commentNew(Request $request, Post $post): Response
    {
        return $this->render('blog/comment_form_error.html.twig');
    }

    /**
     * This controller is called directly via render() — no route.
     *
     * @param Post $post
     */
    public function commentForm(Post $post): Response
    {
        return $this->render('blog/_comment_form.html.twig');
    }
}
`;
    const eps = await detect(src);

    // 3 @Route lines on index → 3 entry points, class prefix "/blog" joined,
    // route regex param preserved verbatim.
    assert(has(eps, 'index', 'GET', '/blog/'), 'index → GET /blog/');
    assert(has(eps, 'index', 'GET', '/blog/rss.xml'), 'index → GET /blog/rss.xml');
    assert(
      has(eps, 'index', 'GET', '/blog/page/{page<[1-9]\\d*>}'),
      'index → GET /blog/page/{page<[1-9]\\d*>} (route regex param preserved)',
    );
    // Method-level route param preserved through joinRoute.
    assert(has(eps, 'postShow', 'GET', '/blog/posts/{slug}'), 'postShow → GET /blog/posts/{slug}');
    // methods={"POST"} captured; mid-path {postSlug} preserved.
    assert(has(eps, 'commentNew', 'POST', '/blog/comment/{postSlug}/new'), 'commentNew → POST /blog/comment/{postSlug}/new');

    // commentForm has a docblock but NO @Route → must NOT be emitted.
    assert(!eps.some((e) => e.handlerName === 'commentForm'), 'commentForm (no @Route in docblock) → not emitted');

    // Route-level evidence classification (entry-point auth arc): commentNew
    // carries @IsGranted("IS_AUTHENTICATED_FULLY") in its docblock →
    // AUTH_INTERNAL; every other route has no security annotation → PUBLIC.
    assert(
      eps.filter((e) => e.handlerName === 'commentNew').every((e) => e.classification === 'AUTH_INTERNAL'),
      'commentNew (@IsGranted IS_AUTHENTICATED_FULLY docblock) → AUTH_INTERNAL',
    );
    assert(
      eps.filter((e) => e.handlerName !== 'commentNew').every((e) => e.classification === 'PUBLIC_UNAUTH'),
      'annotation-less routes stay PUBLIC_UNAUTH',
    );
    // Every entry point is a well-formed http_route row.
    assert(eps.every((e) => e.entryPointType === 'http_route' && e.framework === 'symfony'), 'all rows are symfony http_route');
    assert(eps.length === 5, `exactly 5 entry points emitted (got ${eps.length})`);
  }

  // ---------------------------------------------------------------------------
  // 2. Single-line docblock, no method= (defaults to httpMethod null), no
  //    class prefix.
  // ---------------------------------------------------------------------------
  console.log('\nsingle-line docblock + no class prefix + no methods:');
  {
    const src = `<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

class SecurityController
{
    /** @Route("/login", name="security_login") */
    public function login(): Response
    {
        return $this->render('security/login.html.twig');
    }
}
`;
    const eps = await detect(src);
    assert(eps.length === 1, `single route emitted (got ${eps.length})`);
    assert(has(eps, 'login', null, '/login'), 'login → (ANY) /login (single-line docblock, no methods key)');
  }

  // ---------------------------------------------------------------------------
  // 3. Native #[Route] attribute path still works (regression guard).
  // ---------------------------------------------------------------------------
  console.log('\nnative #[Route] attribute path (regression):');
  {
    const src = `<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

class ApiController
{
    #[Route('/api/users', methods: ['GET', 'POST'])]
    public function users(): Response
    {
        return $this->json([]);
    }
}
`;
    const eps = await detect(src);
    assert(has(eps, 'users', 'GET', '/api/users'), 'users → GET /api/users (attribute)');
    assert(has(eps, 'users', 'POST', '/api/users'), 'users → POST /api/users (attribute)');
    assert(eps.length === 2, `attribute path emits 2 entry points (got ${eps.length})`);
  }

  // ---------------------------------------------------------------------------
  // 4. A method carrying BOTH #[Route] and @Route must not double-count —
  //    prefer the native attribute.
  // ---------------------------------------------------------------------------
  console.log('\nboth #[Route] attribute AND @Route docblock → no double-count:');
  {
    const src = `<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

/**
 * @Route("/legacy")
 */
class MixedController
{
    /**
     * @Route("/from-docblock", methods={"GET"})
     */
    #[Route('/from-attribute', methods: ['PUT'])]
    public function mixed(): Response
    {
        return $this->json([]);
    }
}
`;
    const eps = await detect(src);
    assert(eps.length === 1, `exactly one entry point for the mixed method (got ${eps.length})`);
    assert(has(eps, 'mixed', 'PUT', '/legacy/from-attribute'), 'mixed → PUT /legacy/from-attribute (attribute preferred)');
    assert(!eps.some((e) => (e.routePattern ?? '').includes('from-docblock')), 'docblock route ignored when attribute present');
  }

  // ---------------------------------------------------------------------------
  // 5. Named path= form (Doctrine allows @Route(path="...")).
  // ---------------------------------------------------------------------------
  console.log('\nnamed path= docblock form:');
  {
    const src = `<?php
namespace App\\Controller;

use Symfony\\Component\\Routing\\Annotation\\Route;

class NamedController
{
    /**
     * @Route(path="/search", methods={"GET"}, name="search")
     */
    public function search(): Response
    {
        return $this->json([]);
    }
}
`;
    const eps = await detect(src);
    assert(has(eps, 'search', 'GET', '/search'), 'search → GET /search (named path= form)');
    assert(eps.length === 1, `named path= emits 1 entry point (got ${eps.length})`);
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
