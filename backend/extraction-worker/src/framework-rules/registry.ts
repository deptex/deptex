import type { SupportedLanguageId } from '../tree-sitter-extractor/languages/types';
import type { FrameworkDetector } from './types';
import { expressDetector } from './detectors/express';
import { fastifyDetector } from './detectors/fastify';
import { koaDetector } from './detectors/koa';
import { nestjsDetector } from './detectors/nestjs';
import { nextjsDetector } from './detectors/nextjs';
import { awsLambdaDetector } from './detectors/aws-lambda';
import { flaskDetector } from './detectors/flask';
import { fastapiDetector } from './detectors/fastapi';
import { starletteDetector } from './detectors/starlette';
import { djangoDetector } from './detectors/django';
import { tornadoDetector } from './detectors/tornado';
import { aiohttpDetector } from './detectors/aiohttp';
import { springDetector } from './detectors/spring';
import { jaxrsDetector } from './detectors/jaxrs';
import { quarkusDetector } from './detectors/quarkus';
import { micronautDetector } from './detectors/micronaut';
import { nethttpDetector } from './detectors/nethttp';
import { ginDetector } from './detectors/gin';
import { echoDetector } from './detectors/echo';
import { fiberDetector } from './detectors/fiber';
import { chiDetector } from './detectors/chi';
import { gorillaMuxDetector } from './detectors/gorilla-mux';

/**
 * All registered framework detectors. Adding a new framework is a two-step
 * change: (1) create `detectors/<name>.ts` exporting a `FrameworkDetector`,
 * (2) add it to this list. Detectors self-declare their target language and
 * trigger imports, so the registry stays flat.
 */
const ALL_DETECTORS: readonly FrameworkDetector[] = [
  expressDetector,
  fastifyDetector,
  koaDetector,
  nestjsDetector,
  nextjsDetector,
  awsLambdaDetector,
  flaskDetector,
  fastapiDetector,
  starletteDetector,
  djangoDetector,
  tornadoDetector,
  aiohttpDetector,
  springDetector,
  jaxrsDetector,
  quarkusDetector,
  micronautDetector,
  nethttpDetector,
  ginDetector,
  echoDetector,
  fiberDetector,
  chiDetector,
  gorillaMuxDetector,
];

/** Detectors that might apply to files of the given language. */
export function getDetectorsForLanguage(lang: SupportedLanguageId): FrameworkDetector[] {
  return ALL_DETECTORS.filter((d) => d.language === lang);
}

export function allDetectors(): readonly FrameworkDetector[] {
  return ALL_DETECTORS;
}
