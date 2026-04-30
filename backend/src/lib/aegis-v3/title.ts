import { generateText } from 'ai';
import { supabase } from '../supabase';
import { getAegisModel } from '../aegis/provider';

// Strip leading "Title:" / "Chat title:" labels the model often parrots from
// the prompt, plus surrounding quotes and trailing punctuation. Returns
// "New chat" when nothing usable is left.
export function cleanGeneratedTitle(raw: string): string {
  return (
    raw
      .trim()
      .replace(/^(?:chat\s+)?title\s*[:\-]\s*/i, '')
      .replace(/^["'`]|["'`]$/g, '')
      .replace(/[.?!]+$/, '')
      .trim()
      .slice(0, 80) || 'New chat'
  );
}

// Generate + persist an auto-title for a thread based on its first user/assistant
// exchange. Errors are swallowed — a missing title is a paper cut, not a fatal
// failure. Caller decides whether the thread is on its first exchange (we
// don't want to overwrite a deliberate rename later).
export async function generateThreadTitle(
  threadId: string,
  userText: string,
  assistantText: string,
): Promise<void> {
  try {
    const prompt = `Generate a short title (3-7 words, Title Case, no quotes, no trailing punctuation) for this conversation.

Describe what the user is trying to accomplish — action + target. Use the project, package, or finding name when present in the conversation.
Good examples:
- "Fix Semgrep Finding in deptex-test"
- "Investigate CVE-2024-12345 in api-server"
- "Update Vulnerable Lodash Dependency"
- "Audit Org Security Posture"
- "Plan Reachability Migration"

Avoid status/state words like "Awaiting", "Pending", "Discussion", "Plan Approval".
Output only the title, no "Title:" prefix and no surrounding quotes.

User: ${userText.slice(0, 800)}
Assistant: ${assistantText.slice(0, 800)}`;
    const { text: titleText } = await generateText({ model: getAegisModel(), prompt, temperature: 0.3 });
    const title = cleanGeneratedTitle(titleText);
    await supabase.from('aegis_chat_threads').update({ title }).eq('id', threadId);
  } catch (err) {
    console.error('[aegis] auto-title failed', err);
  }
}
