/**
 * T9 — cross-file auth classification (Rails before_action, Django decorators /
 * mixins / DRF permission_classes). The auth evidence lives in the
 * controller/view file next to the taint sources, so the detectors bank
 * per-action facts during detect and re-home them via postProcess into ctx-only
 * route records keyed on that file. Asserts the postProcess records + that
 * public actions / route files stay untouched.
 *
 * Run: npx tsx test/framework-detector-crossfile-auth.test.ts
 */
import { rubyModule } from '../src/tree-sitter-extractor/languages/ruby';
import { pythonModule } from '../src/tree-sitter-extractor/languages/python';
import { extractWorkspace, dep } from '../src/framework-rules/test-helpers';
import type { CtxOnlyRouteRecord } from '../src/framework-rules/types';

let failures = 0;
let passes = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) { console.error(`  FAIL: ${msg}`); failures++; }
  else { console.log(`  ok: ${msg}`); passes++; }
}
function eq(a: unknown, b: unknown, msg: string): void {
  assert(JSON.stringify(a) === JSON.stringify(b), `${msg} (got ${JSON.stringify(a)}, want ${JSON.stringify(b)})`);
}

/** Classification of the ctx-only record whose span contains `line` in `file`. */
function classAt(records: CtxOnlyRouteRecord[], file: string, line: number): string | null {
  const hit = records.find((r) =>
    r.filePath.includes(file) && r.handlerSpan != null &&
    r.handlerSpan.startLine <= line && line <= r.handlerSpan.endLine);
  return hit ? hit.classification : null;
}

async function run(): Promise<void> {
  // ==========================================================================
  console.log('\nRAILS — before_action / skip / only: / conditional');
  // ==========================================================================
  {
    const controller = `class PostsController < ApplicationController
  before_action :authenticate_user!
  before_action :require_admin, only: [:destroy]
  skip_before_action :authenticate_user!, only: [:index]

  def index
    @q = params[:q]
  end

  def show
    @id = params[:id]
  end

  def destroy
    @id = params[:id]
  end
end
`;
    const { postProcessRecords: recs } = await extractWorkspace(rubyModule, [
      { path: 'app/controllers/posts_controller.rb', source: controller },
    ]);
    // index (line 6-8): before_action authed but skip'd → PUBLIC → no record.
    eq(classAt(recs, 'posts_controller.rb', 7), null, 'index (skip_before_action) → PUBLIC → no demotion record');
    // show (line 10-12): unconditional before_action authenticate_user! → AUTH.
    eq(classAt(recs, 'posts_controller.rb', 11), 'AUTH_INTERNAL', 'show → AUTH_INTERNAL (unconditional before_action)');
    // destroy (line 14-16): authenticate_user! + require_admin only:destroy → AUTH.
    eq(classAt(recs, 'posts_controller.rb', 15), 'AUTH_INTERNAL', 'destroy → AUTH_INTERNAL');
  }
  {
    // Conditional before_action (except:/if:) does NOT cover (Sem 3).
    const controller = `class PublicController < ApplicationController
  before_action :authenticate_user!, except: [:landing]
  before_action :maybe_auth, if: :logged_in?

  def landing
    @q = params[:q]
  end

  def other
    @q = params[:q]
  end
end
`;
    const { postProcessRecords: recs } = await extractWorkspace(rubyModule, [
      { path: 'app/controllers/public_controller.rb', source: controller },
    ]);
    eq(classAt(recs, 'public_controller.rb', 5), null, 'except: kwarg → conditional → NOT covering (Sem 3)');
    eq(classAt(recs, 'public_controller.rb', 9), null, 'if: kwarg → conditional → NOT covering');
  }
  {
    // Non-halting bare `authenticate` is not evidence (Sem 4).
    const controller = `class SoftController < ApplicationController
  before_action :authenticate

  def show
    @q = params[:q]
  end
end
`;
    const { postProcessRecords: recs } = await extractWorkspace(rubyModule, [
      { path: 'app/controllers/soft_controller.rb', source: controller },
    ]);
    eq(classAt(recs, 'soft_controller.rb', 5), null, 'bare non-bang authenticate → not halting → PUBLIC');
  }
  {
    // A routes.rb file produces NO postProcess records (only controllers do),
    // and its route entry points are still persisted (unchanged).
    const routes = `Rails.application.routes.draw do
  get '/posts', to: 'posts#index'
end
`;
    const { files, postProcessRecords: recs } = await extractWorkspace(rubyModule, [
      { path: 'config/routes.rb', source: routes },
    ]);
    eq(recs.length, 0, 'routes.rb alone yields no ctx-only records');
    const routeEps = (files[0].entryPoints ?? []).filter((e) => e.framework === 'rails');
    eq(routeEps.length, 1, 'routes.rb still emits its persisted route entry point');
  }

  // ==========================================================================
  console.log('\nDJANGO — decorators / mixins / DRF permission_classes');
  // ==========================================================================
  {
    const views = `from django.contrib.auth.decorators import login_required
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAuthenticatedOrReadOnly
from rest_framework.generics import ListAPIView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View


def public_view(request):
    return request.GET.get('q')


@login_required
def me_view(request):
    return request.GET.get('q')


class AccountView(LoginRequiredMixin, View):
    def get(self, request):
        return request.GET.get('q')


class ItemsApi(ListAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return request.GET.get('q')


class OpenApi(ListAPIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return request.GET.get('q')


class ReadOnlyApi(ListAPIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request):
        return request.GET.get('q')
`;
    const { postProcessRecords: recs } = await extractWorkspace(pythonModule, [
      { path: 'app/views.py', source: views },
    ], [dep('django')]);

    eq(classAt(recs, 'views.py', 9), null, 'undecorated function view → PUBLIC → no record');
    eq(classAt(recs, 'views.py', 14), 'AUTH_INTERNAL', '@login_required function view → AUTH_INTERNAL');
    eq(classAt(recs, 'views.py', 19), 'AUTH_INTERNAL', 'LoginRequiredMixin CBV get() → AUTH_INTERNAL');
    eq(classAt(recs, 'views.py', 26), 'AUTH_INTERNAL', 'permission_classes=[IsAuthenticated] → AUTH_INTERNAL');
    eq(classAt(recs, 'views.py', 33), null, 'permission_classes=[AllowAny] → explicit PUBLIC → no record');
    eq(classAt(recs, 'views.py', 40), null, 'permission_classes=[IsAuthenticatedOrReadOnly] → conditional → PUBLIC (Sem 3)');
  }

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

run().catch((e) => { console.error(e); process.exit(1); });
