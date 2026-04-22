import { pythonModule } from '../../tree-sitter-extractor/languages/python';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('Python framework detectors', () => {
  describe('flask', () => {
    it('detects @app.route decorators', async () => {
      const file = await extractInline(
        pythonModule,
        `
from flask import Flask

app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def users():
    return {}

@app.route('/ping')
def ping():
    return 'pong'
        `,
        '/tmp/app.py',
        [dep('flask')],
      );
      const eps = entryPointsFor(file, 'flask');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern));
      expect(paths.has('/users')).toBe(true);
      expect(paths.has('/ping')).toBe(true);
    });
  });

  describe('fastapi', () => {
    it('detects @app.get / @app.post', async () => {
      const file = await extractInline(
        pythonModule,
        `
from fastapi import FastAPI

app = FastAPI()

@app.get('/items/{id}')
async def read(id: int):
    return {'id': id}

@app.post('/items')
async def create(body: dict):
    return body
        `,
        '/tmp/api.py',
        [dep('fastapi')],
      );
      const eps = entryPointsFor(file, 'fastapi');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/items/{id}');
      expect(byMethod.get('POST')).toBe('/items');
    });
  });

  describe('starlette', () => {
    it('detects @app.route decorator form', async () => {
      const file = await extractInline(
        pythonModule,
        `
from starlette.applications import Starlette

app = Starlette()

@app.route('/')
async def homepage(request):
    return 'hello'

@app.route('/health')
async def health(request):
    return 'ok'
        `,
        '/tmp/main.py',
        [dep('starlette')],
      );
      const eps = entryPointsFor(file, 'starlette');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern));
      expect(paths.has('/')).toBe(true);
      expect(paths.has('/health')).toBe(true);
    });
  });

  describe('django', () => {
    it('detects urlpatterns path() entries', async () => {
      const file = await extractInline(
        pythonModule,
        `
from django.urls import path
from . import views

urlpatterns = [
    path('articles/<int:year>/', views.year_archive),
    path('admin/', views.admin_dashboard),
]
        `,
        '/tmp/urls.py',
        [dep('django')],
      );
      const eps = entryPointsFor(file, 'django');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern));
      // Detector normalises route patterns to have a leading slash.
      expect(paths.has('/articles/<int:year>/')).toBe(true);
      expect(paths.has('/admin/')).toBe(true);
    });
  });

  describe('tornado', () => {
    it('detects RequestHandler subclasses in URLSpec list', async () => {
      const file = await extractInline(
        pythonModule,
        `
import tornado.web

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write('hello')

class UserHandler(tornado.web.RequestHandler):
    def post(self):
        self.write({})

app = tornado.web.Application([
    (r'/', MainHandler),
    (r'/users', UserHandler),
])
        `,
        '/tmp/server.py',
        [dep('tornado')],
      );
      const eps = entryPointsFor(file, 'tornado');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern));
      expect(paths.has('/')).toBe(true);
      expect(paths.has('/users')).toBe(true);
    });
  });

  describe('aiohttp', () => {
    it('detects RouteTableDef decorators', async () => {
      const file = await extractInline(
        pythonModule,
        `
from aiohttp import web

routes = web.RouteTableDef()

@routes.get('/health')
async def health(request):
    return web.Response(text='ok')

@routes.post('/echo')
async def echo(request):
    return web.Response(text=await request.text())
        `,
        '/tmp/server.py',
        [dep('aiohttp')],
      );
      const eps = entryPointsFor(file, 'aiohttp');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/health');
      expect(byMethod.get('POST')).toBe('/echo');
    });
  });
});
