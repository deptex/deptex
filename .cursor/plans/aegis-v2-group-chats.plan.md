# Aegis Group Chats — Implementation Plan

Sharing Aegis chat threads with other members of the same organization.
Builds on the v2 stack (streaming, tools, thread/message tables).

## Goals
- Any participant can send messages; tool calls run under the **sender's** RBAC, not the thread creator's.
- Only the creator can delete the thread. Non-creators can only leave.
- If the creator leaves the org, creator role transfers to the **oldest-added** remaining participant.
- Restricted users (no `manage_members`) can only invite people they already see under current RBAC. Everyone else is reached via an opt-in **invite code**, redeemed by the recipient themselves.
- Messages stream to all participants in near-real-time. A lightweight typing indicator is shown while others compose.
- If a second user sends a message while Aegis is mid-response, that message is **queued** and processed after the current turn finishes.

## Non-goals (MVP)
- No per-message visibility / read receipts.
- No separate "view-only" participant role.
- No DM lists / org roster browsing via search (respects existing RBAC).
- No cross-org sharing.

---

## Schema

### New: `aegis_chat_participants`
```sql
CREATE TABLE aegis_chat_participants (
  thread_id UUID NOT NULL REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (thread_id, user_id)
);
CREATE INDEX idx_aegis_chat_participants_user_id ON aegis_chat_participants(user_id);
```

### New: `aegis_chat_invite_codes`
One active code per thread. No regeneration; revoke and re-create only.
```sql
CREATE TABLE aegis_chat_invite_codes (
  thread_id UUID PRIMARY KEY REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_aegis_chat_invite_codes_code ON aegis_chat_invite_codes(code) WHERE revoked_at IS NULL;
```

### Changes to `aegis_chat_threads`
Rename/add `created_by` (currently `user_id`). Keep `user_id` column for the transition but treat it as the current owner.
- Option A (clean): rename `user_id` → `created_by`, add trigger/stored proc for owner transfer on org-leave.
- Option B (pragmatic): keep `user_id`, semantically treat as "current owner". On creator-transfer we UPDATE `user_id` to the new oldest participant.

**Going with B.** Less migration risk, easier rollback. Document in code that `aegis_chat_threads.user_id` = current owner, not original creator. Add a new column `created_by UUID` that is immutable, set once at insert, useful for audit only.

```sql
ALTER TABLE aegis_chat_threads
  ADD COLUMN created_by UUID REFERENCES auth.users(id);

-- Backfill existing rows:
UPDATE aegis_chat_threads SET created_by = user_id WHERE created_by IS NULL;

ALTER TABLE aegis_chat_threads
  ALTER COLUMN created_by SET NOT NULL;
```

### Backfill `aegis_chat_participants`
Every existing thread gets a single participant row for its owner:
```sql
INSERT INTO aegis_chat_participants (thread_id, user_id, joined_at)
SELECT id, user_id, created_at FROM aegis_chat_threads
ON CONFLICT DO NOTHING;
```

### Changes to `aegis_chat_messages`
Add `user_id` to identify which participant authored a user message (nullable — assistant messages don't have one).
```sql
ALTER TABLE aegis_chat_messages
  ADD COLUMN user_id UUID REFERENCES auth.users(id);

-- Backfill: all current user rows belong to the thread owner
UPDATE aegis_chat_messages m
SET user_id = t.user_id
FROM aegis_chat_threads t
WHERE m.thread_id = t.id AND m.role = 'user' AND m.user_id IS NULL;
```

### RLS
Replace the "owner only" rule on `aegis_chat_threads` with "participant". Same on `aegis_chat_messages`.
```sql
DROP POLICY IF EXISTS "Users can view their own aegis threads" ON aegis_chat_threads;
CREATE POLICY "Participants can view aegis threads"
  ON aegis_chat_threads FOR SELECT
  USING (id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));

-- aegis_chat_messages: same pattern, keyed by participant membership
DROP POLICY IF EXISTS "Users can view their own aegis messages" ON aegis_chat_messages;
CREATE POLICY "Participants can view aegis messages"
  ON aegis_chat_messages FOR SELECT
  USING (thread_id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));
```
(Exact rewording depends on current policies — audit before migrating.)

---

## Backend

### Access-check helper
Centralize in `backend/src/lib/aegis/participants.ts`:
```ts
isParticipant(threadId, userId): Promise<boolean>
isCreator(threadId, userId): Promise<boolean>
listParticipants(threadId): Promise<Array<{user_id, joined_at, is_creator}>>
addParticipant(threadId, userId): Promise<void>       // no-op if already present
removeParticipant(threadId, userId): Promise<void>
transferOwnership(threadId, fromUserId): Promise<string | null>  // returns new owner id
```

Replace every existing `ensureThreadOwnership` call with `isParticipant` except for:
- DELETE `/threads/:id` → must be `isCreator`.
- `transferOwnership` trigger logic (see below).

### Updated routes in `backend/src/routes/aegis.ts`

| Route | Change |
|---|---|
| `GET /threads` | Select threads where viewer is participant. Order pinned-first, then updated_at desc. |
| `GET /threads/:id/messages` | Require `isParticipant`. |
| `POST /threads` | On insert, also INSERT into `aegis_chat_participants` for the creator. Set `created_by = user_id`. |
| `PATCH /threads/:id` | Any participant can rename/pin/archive **for themselves**? Decision: rename/archive/pin are **per-thread**, not per-user, so only creator can rename/archive/pin/unpin. (Otherwise one user's pin affects everyone.) |
| `DELETE /threads/:id` | Require `isCreator`. |
| `POST /chat` | Require `isParticipant`. Persist user message with `user_id = senderId`. Tool context uses `senderId` (per-message RBAC). |
| `POST /threads/:id/auto-title` | Any participant can trigger (but it normally fires once). |

**New routes:**
| Route | Purpose |
|---|---|
| `GET /threads/:id/participants` | List participants with display names/avatars. Participants only. |
| `POST /threads/:id/participants` `{ userId }` | Add a user. Caller must be participant. Server-side check: caller has visibility to target user under org RBAC (see visibility helper). Responds 403 if not. |
| `DELETE /threads/:id/participants/:userId` | Remove participant. Creator only, OR self (leave). Leaving-creator triggers ownership transfer. |
| `GET /threads/:id/invite-code` | Returns active code (or null). Participants only. |
| `POST /threads/:id/invite-code` | Create a code. Errors if one already active. Participants only. |
| `DELETE /threads/:id/invite-code` | Revoke the active code. Participants only. |
| `POST /invite/redeem` `{ code }` | Join the associated thread. Caller must be in the same org as the thread and have `interact_with_aegis`. Adds to `aegis_chat_participants`. Returns `{ threadId }`. |

### Visibility helper for "who can I invite?"
`listInvitableUsers(inviterUserId, orgId)` returns users visible to `inviterUserId` under current RBAC.
- If inviter has `manage_members` or `view_all_teams_and_projects`: return all org members.
- Else: return members of teams the inviter is on, plus members of projects the inviter is assigned to.
(Excludes the inviter themselves and anyone already a participant.)

Endpoint: `GET /organizations/:orgId/aegis/invitable-users?threadId=...`

### Per-message RBAC for tool calls
Backend `/chat` already uses `userId` in the tool context. The change is: when a non-creator participant sends a message, treat `senderId` as the tool context's userId. Every tool currently checks `project.organization_id === ctx.organizationId` — that still works. No tool-level changes needed.

Add to the system prompt: "The authenticated user sending this message is `{senderName}` with role `{roleName}`. Their available tools may be restricted by their role."

### Creator transfer
When DELETE `/participants/:userId` and that user is the creator (`thread.user_id === userId`):
1. Pick oldest other participant: `ORDER BY joined_at ASC LIMIT 1`.
2. If none: delete the thread (orphaned).
3. If found: `UPDATE aegis_chat_threads SET user_id = newOwnerId WHERE id = threadId`.
4. Delete the old participant row.

Also wire a **separate trigger**: when a user is removed from `organization_members`, find all threads in that org where they are the owner, and run the same transfer logic. Postgres function + trigger on `organization_members` DELETE. (This handles the "creator leaves org" edge case Henry confirmed in edge case #3.)

### Message queueing
When a participant POSTs `/chat` and the thread has an in-flight assistant turn:
- Detection: track `active_stream_until TIMESTAMPTZ` on `aegis_chat_threads` (null = idle). Set at stream start, cleared on finish. Stale streams (older than 5 min) treated as idle.
- If active: persist the user message immediately (so it's visible to everyone), then **do not** invoke `streamText` — instead enqueue by setting a `pending_turn` flag (could be implicit — just: on stream finish, check if newest message is a user message without an assistant response; if yes, kick off another `streamText` with the full history).
- Orchestrator: wrap `streamText` in a loop in the chat route that runs until the newest row is an assistant message.

This keeps the implementation simple and stateless across requests — the second user's POST just adds a message and returns immediately; the first user's stream finishes and auto-continues with the now-expanded history.

**Alternative simpler approach:** reject the second POST with 409 "Stream in progress, retry in a sec" and let the frontend retry on stream-finish. Less elegant but fewer moving parts. **Starting with this** for MVP; upgrade to the loop pattern later if it's a pain.

---

## Realtime

Use Supabase Realtime on `aegis_chat_messages` channel filtered by `thread_id`:
```ts
supabase
  .channel(`aegis-thread-${threadId}`)
  .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'aegis_chat_messages', filter: `thread_id=eq.${threadId}` }, handler)
  .subscribe();
```

The local `useChat` state is authoritative for messages **I** sent; for messages from other participants we merge inserts from Realtime into `messages` via `setMessages`.

### Typing indicator
Broadcast channel (ephemeral, not persisted):
```ts
supabase.channel(`aegis-typing-${threadId}`).send({
  type: 'broadcast', event: 'typing',
  payload: { userId, typing: true, displayName }
});
```
Debounce to send `typing: true` on keydown and `typing: false` after 2s of no keystrokes or on send. Display a row like "Alice is typing…" below the last message.

### Channel permissions
Supabase Realtime respects RLS on `postgres_changes`, so as long as the participant RLS policy is in place, only participants receive inserts. Broadcast channels are not RLS-gated by default — fine for typing since it leaks nothing sensitive (and both parties are participants anyway).

---

## Frontend

### New state in `ChatPane`
- `participants: Array<{ userId, displayName, avatarUrl, isCreator }>` loaded once on mount.
- `typingUsers: Record<userId, { displayName, lastPing }>` updated by broadcast handler.
- Realtime subscription to message inserts; on insert from another user, `setMessages(prev => [...prev, uiMessageFromRow])`.

### `MessageBubble` changes
Accept a `participant` prop for user messages. Render `participant.displayName` instead of hard-coded "You" when the message is from someone else. Avatar if available.

### New components
- `ParticipantsPanel.tsx` — slide-over or dropdown showing the participant list with "Remove" (creator only) + "Leave" (self) + invite code section. Opens from a Users icon in the ChatPane header.
- `AddPeopleModal.tsx` — search box over `listInvitableUsers` results; bottom shows "Can't find them? Copy invite code. Anyone with this code can join." + revoke button.
- `JoinByCodeModal.tsx` — code input + Join button. Triggered from a "Join chat by code" menu item at the top of the thread list (under "New chat").
- `TypingIndicator.tsx` — small inline row like "Alice is typing…" (handles 1, 2, "Alice and 2 others are typing").

### Thread list changes
- Shared threads show a small Users icon badge. Tooltip: "3 participants".
- Rename/pin/archive menu items are hidden for non-creators (those actions are creator-only per decision above).
- New "Leave" menu item for non-creators.

### ChatInput while streaming
On the current user's ChatPane, disable the input during stream as today. **Also** show an inline hint when a *different* participant's stream is active: "Aegis is responding to someone else…" and queue our send until finish. Implementation: track `otherStreamActive: boolean` set when we see a new user message from someone else and the last assistant message hasn't come in yet; unset when assistant message arrives. If the user hits send during this window, show a toast "Wait for Aegis to finish responding" (matches MVP 409 approach).

---

## Migration order

1. **Schema migrations** (two files):
   - `phase21_aegis_v2_participants.sql` — creates `aegis_chat_participants`, backfills owners, adds `aegis_chat_threads.created_by`, backfills it, replaces RLS.
   - `phase21_aegis_v2_invite_codes.sql` — creates `aegis_chat_invite_codes`.
   - `phase21_aegis_v2_message_author.sql` — adds `aegis_chat_messages.user_id`, backfills.

2. **Postgres trigger** for creator-transfer on `organization_members` DELETE. SECURITY DEFINER function that transfers ownership to oldest participant.

3. **Backend**: participants helper, route updates, new routes (participants, invite codes, redeem), visibility helper.

4. **Backend streaming guard**: 409 rejection on concurrent stream.

5. **Frontend scaffolding**: ParticipantsPanel, AddPeopleModal, JoinByCodeModal.

6. **Frontend realtime**: message insert subscription, typing broadcast.

7. **Dogfood pass**: two users in the same browser profile / two sessions. Rename to a shared name. Archive the thread from one user and verify it's archived for everyone (since archive is per-thread, not per-user). Leave as non-creator and verify disappearance. Creator leaves and verify ownership transfer.

## Resolved decisions (2026-04-20)

- **Pin + archive are per-user.** Drop `pinned_at`/`archived_at` from `aegis_chat_threads` (we shipped them in phase 21 before this decision). Add `aegis_chat_user_state (thread_id, user_id, pinned_at, archived_at, PK(thread_id, user_id))`. List endpoint LEFT JOINs on user_state for the viewer. Rename stays per-thread (creator only).
- **Invite picker visibility = shared teams + shared projects.** Includes both vectors.
- **Concurrent sends queue on the backend.** Drop the 409-reject MVP; implement the loop pattern (after `streamText` finishes, re-check whether newest row is a user message with no assistant response; if so, run another `streamText` with expanded history). Only a single in-flight stream per thread.
- **Recipient without `interact_with_aegis`** redeeming a code: 403 with "You don't have the Aegis permission — ask an admin."
