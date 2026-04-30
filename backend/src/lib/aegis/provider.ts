import { createGoogleGenerativeAI } from '@ai-sdk/google';

const DEFAULT_MODEL = 'gemini-2.5-flash';

let cachedProvider: ReturnType<typeof createGoogleGenerativeAI> | null = null;

function getProvider() {
  if (cachedProvider) return cachedProvider;
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) {
    throw new Error('GOOGLE_AI_API_KEY is not configured — Aegis v2 requires it.');
  }
  cachedProvider = createGoogleGenerativeAI({ apiKey });
  return cachedProvider;
}

export function getAegisModel(modelId: string = DEFAULT_MODEL) {
  return getProvider()(modelId);
}
