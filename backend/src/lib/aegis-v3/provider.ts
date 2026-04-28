import { createGoogleGenerativeAI } from '@ai-sdk/google';
import type { EmbeddingModel } from 'ai';

export { getLanguageModelForOrg, getProviderInfoForOrg } from '../aegis/llm-provider';

export function getEmbeddingModel(): EmbeddingModel {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY required for memory embeddings');
  return createGoogleGenerativeAI({ apiKey }).embedding('gemini-embedding-001');
}
