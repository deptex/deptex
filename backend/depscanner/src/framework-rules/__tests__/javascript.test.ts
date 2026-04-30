import { javascriptModule } from '../../tree-sitter-extractor/languages/javascript';
import { dep, entryPointsFor, extractInline } from '../test-helpers';

describe('JavaScript framework detectors', () => {
  describe('express', () => {
    it('detects app.get route', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          const express = require('express');
          const app = express();
          app.get('/users', (req, res) => res.json([]));
          app.post('/users/:id', (req, res) => res.status(201).end());
        `,
        '/tmp/app.js',
        [dep('express')],
      );
      const eps = entryPointsFor(file, 'express');
      expect(eps).toHaveLength(2);
      const methods = eps.map((e) => e.httpMethod).sort();
      expect(methods).toEqual(['GET', 'POST']);
      expect(eps.every((e) => e.entryPointType === 'http_route')).toBe(true);
    });

    it('detects router mounted from imported factory', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          import express from 'express';
          const router = express.Router();
          router.delete('/items/:id', handler);
        `,
        '/tmp/routes.js',
        [dep('express')],
      );
      const eps = entryPointsFor(file, 'express');
      expect(eps.length).toBeGreaterThan(0);
      expect(eps.some((e) => e.routePattern === '/items/:id' && e.httpMethod === 'DELETE')).toBe(true);
    });
  });

  describe('fastify', () => {
    it('detects fastify.get via builder IIFE', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          const fastify = require('fastify')({ logger: true });
          fastify.get('/ping', async () => ({ pong: true }));
          fastify.post('/upload', async (req) => req.body);
        `,
        '/tmp/server.js',
        [dep('fastify')],
      );
      const eps = entryPointsFor(file, 'fastify');
      expect(eps).toHaveLength(2);
      const paths = eps.map((e) => e.routePattern).sort();
      expect(paths).toEqual(['/ping', '/upload']);
    });
  });

  describe('koa', () => {
    it('detects router.get from @koa/router', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          const Router = require('@koa/router');
          const router = new Router();
          router.get('/health', (ctx) => { ctx.body = 'ok'; });
          router.put('/users/:id', updateUser);
        `,
        '/tmp/router.js',
        [dep('@koa/router')],
      );
      const eps = entryPointsFor(file, 'koa');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      expect(eps.some((e) => e.routePattern === '/health' && e.httpMethod === 'GET')).toBe(true);
      expect(eps.some((e) => e.routePattern === '/users/:id' && e.httpMethod === 'PUT')).toBe(true);
    });
  });

  describe('nestjs', () => {
    it('detects controller + route decorators', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          import { Controller, Get, Post } from '@nestjs/common';

          @Controller('users')
          class UsersController {
            @Get(':id')
            findOne(id) { return {}; }

            @Post()
            create(body) { return body; }
          }
        `,
        '/tmp/users.controller.ts',
        [dep('@nestjs/common')],
      );
      const eps = entryPointsFor(file, 'nestjs');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const pathsByMethod = new Map(eps.map((e) => [e.httpMethod, e.routePattern]));
      expect(pathsByMethod.get('GET')).toContain(':id');
      expect(pathsByMethod.has('POST')).toBe(true);
    });
  });

  describe('nextjs', () => {
    it('detects App Router route.ts export', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          export async function GET(req) { return Response.json({ ok: true }); }
          export async function POST(req) { return Response.json({ created: true }); }
        `,
        '/project/app/api/users/route.ts',
        [],
      );
      const eps = entryPointsFor(file, 'nextjs');
      expect(eps.length).toBeGreaterThanOrEqual(2);
      const methods = new Set(eps.map((e) => e.httpMethod));
      expect(methods.has('GET')).toBe(true);
      expect(methods.has('POST')).toBe(true);
    });
  });

  describe('aws-lambda', () => {
    it('detects export const handler', async () => {
      const file = await extractInline(
        javascriptModule,
        `
          exports.handler = async (event) => {
            return { statusCode: 200, body: JSON.stringify(event) };
          };
        `,
        '/project/lambda/index.js',
        [],
      );
      const eps = entryPointsFor(file, 'aws-lambda');
      expect(eps.length).toBeGreaterThanOrEqual(1);
      expect(eps[0].entryPointType).toBe('serverless_handler');
    });
  });
});
