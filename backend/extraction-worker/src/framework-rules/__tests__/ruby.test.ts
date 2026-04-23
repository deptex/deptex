import { rubyModule } from '../../tree-sitter-extractor/languages/ruby';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('Ruby framework detectors', () => {
  describe('sinatra', () => {
    it('detects top-level get/post blocks', async () => {
      const file = await extractInline(
        rubyModule,
        `
require 'sinatra'

get '/hello' do
  'Hello, world!'
end

post '/echo' do
  request.body.read
end
        `,
        '/tmp/app.rb',
        [dep('sinatra')],
      );
      const eps = entryPointsFor(file, 'sinatra');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/hello');
      expect(byMethod.get('POST')).toBe('/echo');
    });
  });

  describe('rails', () => {
    it('detects config/routes.rb resources/get lines', async () => {
      const file = await extractInline(
        rubyModule,
        `
Rails.application.routes.draw do
  resources :users
  get '/health', to: 'application#health'
  post '/webhooks/:provider', to: 'webhooks#receive'
end
        `,
        '/project/config/routes.rb',
        [dep('rails')],
      );
      const eps = entryPointsFor(file, 'rails');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const paths = new Set(eps.map((e) => e.routePattern).filter(Boolean));
      expect(paths.has('/health')).toBe(true);
      expect(paths.has('/webhooks/:provider')).toBe(true);
    });
  });

  describe('grape', () => {
    it('detects Grape::API get/post declarations', async () => {
      const file = await extractInline(
        rubyModule,
        `
require 'grape'

class PublicAPI < Grape::API
  format :json

  get '/status' do
    { ok: true }
  end

  post '/users' do
    { created: params[:name] }
  end
end
        `,
        '/tmp/api.rb',
        [dep('grape')],
      );
      const eps = entryPointsFor(file, 'grape');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const byMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(byMethod.get('GET')).toBe('/status');
      expect(byMethod.get('POST')).toBe('/users');
    });
  });
});
