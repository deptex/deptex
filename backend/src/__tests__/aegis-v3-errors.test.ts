import { classifyChatError, chatErrorUserText } from '../lib/aegis/errors';
import { cleanGeneratedTitle } from '../lib/aegis/title';
import { stepsToMessageParts } from '../lib/aegis/parts';

describe('classifyChatError', () => {
  it('maps statusCode 429 to rate_limit', () => {
    const result = classifyChatError({ statusCode: 429, message: 'Model busy' });
    expect(result.type).toBe('rate_limit');
    expect(result.statusCode).toBe(429);
  });

  it('reads statusCode from RetryError.lastError', () => {
    const result = classifyChatError({
      message: 'Failed after 3 attempts',
      lastError: { statusCode: 429, message: 'Model busy' },
    });
    expect(result.type).toBe('rate_limit');
  });

  it('maps AbortError to transient with cancelled message', () => {
    const err = new Error('aborted');
    err.name = 'AbortError';
    const result = classifyChatError(err);
    expect(result.type).toBe('transient');
    expect(result.message).toBe('Stream cancelled');
  });

  it('falls through to transient with the underlying status when not 429', () => {
    const result = classifyChatError({ statusCode: 503, message: 'Service unavailable' });
    expect(result.type).toBe('transient');
    expect(result.statusCode).toBe(503);
    expect(result.message).toBe('Service unavailable');
  });

  it('handles plain unknown errors gracefully', () => {
    const result = classifyChatError(new Error('something broke'));
    expect(result.type).toBe('transient');
    expect(result.statusCode).toBeUndefined();
    expect(result.message).toBe('something broke');
  });
});

describe('chatErrorUserText', () => {
  it('uses the cap-specific message for cost_cap', () => {
    expect(chatErrorUserText({ type: 'cost_cap', message: 'Budget reached.' })).toBe(
      'Budget reached.',
    );
  });

  it('falls back to a generic line when cost_cap has no message', () => {
    expect(chatErrorUserText({ type: 'cost_cap' })).toBe('Monthly AI budget reached.');
  });

  it('uses the same generic line for rate_limit and transient', () => {
    expect(chatErrorUserText({ type: 'rate_limit' })).toBe(
      'Something went wrong while generating a response.',
    );
    expect(chatErrorUserText({ type: 'transient' })).toBe(
      'Something went wrong while generating a response.',
    );
  });
});

describe('cleanGeneratedTitle', () => {
  it('strips a leading "Title:" prefix the model parrots from the prompt', () => {
    expect(cleanGeneratedTitle('Title: Initiate Deptex Tasks')).toBe('Initiate Deptex Tasks');
  });

  it('strips "Chat title -" variants too', () => {
    expect(cleanGeneratedTitle('Chat title - Audit Org Posture')).toBe('Audit Org Posture');
  });

  it('strips wrapping quotes and trailing punctuation', () => {
    expect(cleanGeneratedTitle('"Fix Lodash CVE!"')).toBe('Fix Lodash CVE');
  });

  it('falls back to "New chat" on empty input', () => {
    expect(cleanGeneratedTitle('   ')).toBe('New chat');
    expect(cleanGeneratedTitle('Title:')).toBe('New chat');
  });

  it('truncates extremely long titles to 80 chars', () => {
    const long = 'A'.repeat(200);
    expect(cleanGeneratedTitle(long).length).toBe(80);
  });
});

describe('stepsToMessageParts', () => {
  it('lifts step text into a text part', () => {
    const parts = stepsToMessageParts([{ text: 'Hello world' }]);
    expect(parts).toEqual([{ type: 'text', text: 'Hello world' }]);
  });

  it('emits paired tool-call + tool-result for resolved tool steps', () => {
    const parts = stepsToMessageParts([
      {
        toolCalls: [{ toolCallId: 'tc1', toolName: 'read_dep', input: { name: 'lodash' } }],
        toolResults: [{ toolCallId: 'tc1', toolName: 'read_dep', output: { version: '4.17.21' } }],
      },
    ]);
    expect(parts).toHaveLength(2);
    expect(parts[0]).toEqual({
      type: 'tool-call',
      toolCallId: 'tc1',
      toolName: 'read_dep',
      args: { name: 'lodash' },
    });
    expect(parts[1]).toEqual({
      type: 'tool-result',
      toolCallId: 'tc1',
      toolName: 'read_dep',
      result: { version: '4.17.21' },
    });
  });

  it('marks tool-result as isError when the output has an error key', () => {
    const parts = stepsToMessageParts([
      {
        toolCalls: [{ toolCallId: 'tc1', toolName: 'fail', input: {} }],
        toolResults: [{ toolCallId: 'tc1', toolName: 'fail', output: { error: 'boom' } }],
      },
    ]);
    expect((parts[1] as { isError?: boolean }).isError).toBe(true);
  });

  it('handles a step with text and tool calls in the same turn', () => {
    const parts = stepsToMessageParts([
      {
        text: 'Looking up the dep…',
        toolCalls: [{ toolCallId: 'tc1', toolName: 'read', input: {} }],
        toolResults: [{ toolCallId: 'tc1', toolName: 'read', output: 'ok' }],
      },
    ]);
    expect(parts.map((p) => p.type)).toEqual(['text', 'tool-call', 'tool-result']);
  });
});
