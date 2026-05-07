import type { AIModelMetadata, PlatformAIProvider } from '../lib/api';

export type ModelBrand = PlatformAIProvider | 'deepseek' | 'qwen' | 'moonshot';

const PROVIDER_ASSET: Record<ModelBrand, { src: string; alt: string }> = {
  anthropic: { src: '/images/providers/anthropic.png', alt: 'Anthropic' },
  openai:    { src: '/images/providers/openai.png',    alt: 'OpenAI' },
  google:    { src: '/images/providers/google.png',    alt: 'Google' },
  deepinfra: { src: '/images/providers/deepinfra.png', alt: 'DeepInfra' },
  deepseek:  { src: '/images/providers/deepseek.png',  alt: 'DeepSeek' },
  qwen:      { src: '/images/providers/qwen.png',      alt: 'Qwen' },
  moonshot:  { src: '/images/providers/moonshot.svg',  alt: 'Moonshot AI' },
};

// DeepInfra hosts open-weight models — show the *model* brand (DeepSeek,
// Qwen, Moonshot, etc.) rather than the host's mark.
export function brandForModel(model: Pick<AIModelMetadata, 'id' | 'provider'>): ModelBrand {
  if (model.id.startsWith('deepseek-ai/')) return 'deepseek';
  if (model.id.startsWith('Qwen/')) return 'qwen';
  if (model.id.startsWith('moonshotai/')) return 'moonshot';
  return model.provider;
}

export function AIProviderIcon({
  brand,
  size = 16,
  className,
}: {
  brand: ModelBrand;
  size?: number;
  className?: string;
}) {
  const asset = PROVIDER_ASSET[brand];
  return (
    <img
      src={asset.src}
      width={size}
      height={size}
      alt={asset.alt}
      className={className}
    />
  );
}
