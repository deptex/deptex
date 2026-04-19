import OpenAI from 'openai';

// Lazy initialization - only create client when first accessed
let _openai: OpenAI | null = null;

export function getOpenAIClient(): OpenAI {
    if (_openai) return _openai;

    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) {
        throw new Error('OPENAI_API_KEY environment variable is missing. Please add it to your .env file.');
    }

    _openai = new OpenAI({
        apiKey: apiKey,
    });

    return _openai;
}
