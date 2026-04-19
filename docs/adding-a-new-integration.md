# Adding a New Integration

Deptex supports three categories of integrations: **CI/CD** (GitHub, GitLab, Bitbucket), **Notifications** (Slack, Discord), and **Ticketing** (Jira, Linear, Asana). Each uses OAuth or token-based authentication stored in `organization_integrations`.

For users who want a quick integration without writing code, Deptex also supports **Custom Webhook Integrations** — see the [Custom Webhooks](#custom-webhook-integrations) section.

---

## Quick start — add an integration in 3 files

### 1. Add the backend route

**File:** `ee/backend/routes/integrations.ts`

Add two routes: an install endpoint (initiates OAuth) and a callback endpoint (handles the redirect).

```typescript
router.get('/yourprovider/install', authenticateUser, async (req: AuthRequest, res) => {
  const { org_id } = req.query;
  if (!org_id || typeof org_id !== 'string') {
    return res.status(400).json({ error: 'Organization ID is required' });
  }
  // Verify membership, then build OAuth URL
  const state = Buffer.from(JSON.stringify({ userId: req.user!.id, orgId: org_id })).toString('base64');
  const authUrl = `https://provider.com/oauth/authorize?client_id=${process.env.YOURPROVIDER_CLIENT_ID}&state=${state}&redirect_uri=...`;
  res.json({ redirectUrl: authUrl });
});

router.get('/yourprovider/org-callback', async (req, res) => {
  // Exchange code for token, fetch display info, insert into organization_integrations
  await supabase.from('organization_integrations').insert({
    organization_id: orgId,
    provider: 'yourprovider',
    installation_id: uniqueId,
    display_name: displayName,
    access_token: token,
    status: 'connected',
    metadata: { /* provider-specific data */ },
    connected_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  res.redirect(`${frontendUrl}/organizations/${orgId}/settings/integrations?connected=yourprovider`);
});
```

Update the connections query to include your provider:

```typescript
.in('provider', ['github', 'gitlab', 'bitbucket', 'slack', 'discord', 'jira', 'linear', 'asana', 'yourprovider', ...])
```

### 2. Add the frontend API method

**File:** `frontend/src/lib/api.ts`

Add the provider to the `CiCdProvider` type union and add a connect method:

```typescript
export type CiCdProvider = '...' | 'yourprovider';

// In the api object:
async connectYourProviderOrg(organizationId: string): Promise<{ redirectUrl: string }> {
  return fetchWithAuth(`/api/integrations/yourprovider/install?org_id=${organizationId}`);
},
```

### 3. Add the frontend UI

**File:** `frontend/src/app/pages/OrganizationSettingsPage.tsx`

Add your provider to the appropriate section:

- **For notifications:** Add to `notificationConnections` filter and the buttons array
- **For ticketing:** Add to `ticketingConnections` filter and the buttons array
- **For CI/CD:** Add to the existing CI/CD section

Add an "Add YourProvider" button and handle the provider in the table row rendering.

Place your provider icon at `frontend/public/images/integrations/yourprovider.png` (square, ideally 256×256 or larger).

---

## Architecture

### Integration pipeline

```
User clicks "Add Provider"
    → Frontend calls /api/integrations/provider/install
    → Backend returns OAuth redirect URL
    → User authorizes on provider site
    → Provider redirects to /api/integrations/provider/org-callback
    → Backend exchanges code for token
    → Backend stores connection in organization_integrations
    → Backend redirects to frontend with ?connected=provider
    → Frontend shows success toast and reloads connections
```

### Key files

| File | Role |
|------|------|
| `ee/backend/routes/integrations.ts` | All integration routes (OAuth, callbacks, CRUD, webhooks) |
| `frontend/src/lib/api.ts` | TypeScript API client with auth methods for each provider |
| `frontend/src/app/pages/OrganizationSettingsPage.tsx` | Settings UI with tables for each integration category |
| `backend/database/organization_integrations_schema.sql` | Database schema for `organization_integrations` table |
| `backend/database/migration_multi_provider_integrations.sql` | Migration enabling multiple connections per provider |
| `ee/backend/lib/github.ts` | GitHub-specific API helpers (tokens, check runs, PR comments) |

### Database schema

All integrations are stored in `organization_integrations`:

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `organization_id` | UUID | FK to organizations |
| `provider` | TEXT | Provider identifier (e.g. `slack`, `jira`, `custom_notification`) |
| `installation_id` | TEXT | Provider-specific unique ID (used in unique constraint) |
| `display_name` | TEXT | Human-readable name shown in the UI |
| `access_token` | TEXT | OAuth token or HMAC secret (for custom integrations) |
| `refresh_token` | TEXT | OAuth refresh token (if applicable) |
| `metadata` | JSONB | Provider-specific data (webhook URLs, channel info, etc.) |
| `status` | TEXT | `connected`, `disconnected`, `error`, `suspended` |
| `connected_at` | TIMESTAMPTZ | When the connection was established |

Unique constraint: `(organization_id, provider, installation_id)` — allows multiple connections of the same provider type (e.g. Slack to different channels).

---

## Supported integrations

| Provider | Category | Auth Method | Env Vars |
|----------|----------|-------------|----------|
| GitHub | CI/CD | GitHub App | `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` |
| GitLab | CI/CD | OAuth 2.0 | `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET` |
| Bitbucket | CI/CD | OAuth 2.0 | `BITBUCKET_CLIENT_ID`, `BITBUCKET_CLIENT_SECRET` |
| Slack | Notifications | OAuth 2.0 | `SLACK_CLIENT_ID`, `SLACK_CLIENT_SECRET` |
| Discord | Notifications | OAuth 2.0 (Bot) | `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_BOT_TOKEN` |
| Jira Cloud | Ticketing | Atlassian OAuth 2.0 | `JIRA_CLIENT_ID`, `JIRA_CLIENT_SECRET` |
| Jira Data Center | Ticketing | Personal Access Token | (user-provided URL + PAT) |
| Linear | Ticketing | OAuth 2.0 | `LINEAR_CLIENT_ID`, `LINEAR_CLIENT_SECRET` |
| Asana | Ticketing | OAuth 2.0 | `ASANA_CLIENT_ID`, `ASANA_CLIENT_SECRET` |
| Custom | Notifications/Ticketing | HMAC-SHA256 Webhook | (user-provided webhook URL) |

---

## Step-by-step: adding a notification provider

Using Slack as a reference implementation.

### 1. Register your OAuth app with the provider

Set up an OAuth app on the provider's developer portal. You'll need:
- **Client ID** and **Client Secret** (stored as env vars)
- **Redirect URI**: `{BACKEND_URL}/api/integrations/yourprovider/org-callback`
- **Scopes**: whatever your provider needs for sending messages

### 2. Add the install route

The install route validates org membership, builds an OAuth URL with a state parameter (containing `userId` and `orgId`), and returns it as JSON:

```typescript
router.get('/yourprovider/install', authenticateUser, async (req: AuthRequest, res) => {
  // 1. Validate org_id query param
  // 2. Check membership in organization_members
  // 3. Build OAuth URL with state = base64({ userId, orgId })
  // 4. res.json({ redirectUrl })
});
```

### 3. Add the callback route

The callback route exchanges the auth code for a token, fetches provider metadata (workspace/server name), and stores the connection:

```typescript
router.get('/yourprovider/org-callback', async (req, res) => {
  // 1. Parse state to get userId, orgId
  // 2. Verify membership
  // 3. Exchange code for token via provider's token endpoint
  // 4. Fetch display info (workspace name, etc.)
  // 5. Insert into organization_integrations
  // 6. Redirect to frontend with ?connected=yourprovider
});
```

### 4. Update the connections query

In the `GET /organizations/:orgId/connections` handler, add your provider to the `.in('provider', [...])` filter.

### 5. Add the frontend

- Add provider to `CiCdProvider` type in `api.ts`
- Add `connectYourProviderOrg()` method in `api.ts`
- Add to `notificationConnections` filter in `OrganizationSettingsPage.tsx`
- Add "Add YourProvider" button
- Handle provider in table row rendering (icon, display name, disconnect)

### 6. Add the provider icon

Place a PNG icon at `frontend/public/images/integrations/yourprovider.png`.

---

## Step-by-step: adding a ticketing provider

The same process as notifications, but:
- Add to the `ticketingConnections` filter instead of `notificationConnections`
- Add buttons in the Ticketing section header
- When ticket creation is implemented later, add the ticket creation logic to the appropriate event handlers

---

## Custom webhook integrations

For users who don't want to (or can't) write a full integration provider, Deptex supports **Custom Webhook Integrations** — a bring-your-own-endpoint approach available for both notifications and ticketing.

Custom integrations are available in the organization Settings > Integrations page under both the Notifications and Ticketing sections via the "Add Custom" button.

### How custom webhooks work

1. User clicks "Add Custom" in either the Notifications or Ticketing section
2. A dialog opens where the user enters: **name**, **webhook URL**, and optionally uploads an **icon**
3. On creation, the backend generates an HMAC-SHA256 signing secret (`whsec_` prefix)
4. The dialog closes and the signing secret is shown **inline in the table row** with a copy button — this is the only time it's visible
5. The custom integration appears in the table with the webhook icon (or uploaded icon), name, and truncated webhook URL
6. When events fire, Deptex POSTs to the webhook URL with:
   - `X-Deptex-Signature: sha256=<hmac_hex>` — HMAC-SHA256 of the request body using the secret
   - `X-Deptex-Event: <event_type>` — the event type (e.g. `vulnerability.found`)
   - `Content-Type: application/json`

### Managing custom integrations

- **Edit**: Hover over the row and click the pencil icon to update the name, webhook URL, or icon
- **Regenerate secret**: Available in the edit dialog — generates a new secret and invalidates the old one immediately
- **Remove**: Hover over the row and click "Remove" to delete the integration

### Backend endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/organizations/:orgId/custom-integrations` | Create a custom integration (returns signing secret) |
| `PUT` | `/organizations/:orgId/custom-integrations/:id` | Update name, webhook URL, icon, or regenerate secret |
| `POST` | `/organizations/:orgId/custom-integrations/upload-icon` | Upload a PNG/JPEG/WebP icon (max 256KB) |
| `DELETE` | `/organizations/:orgId/connections/:connectionId` | Remove a custom integration (uses shared endpoint) |

Custom integrations are stored in the same `organization_integrations` table with `provider = 'custom_notification'` or `provider = 'custom_ticketing'`. The HMAC secret is stored in the `access_token` column. The webhook URL and icon URL are stored in `metadata`.

### Verifying signatures

```python
# Python example
import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = 'sha256=' + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)
```

```typescript
// Node.js example
import { createHmac, timingSafeEqual } from 'crypto';

function verifySignature(payload: string, signature: string, secret: string): boolean {
  const expected = 'sha256=' + createHmac('sha256', secret).update(payload).digest('hex');
  return timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}
```

### Event types

| Event | Description |
|-------|-------------|
| `vulnerability.found` | A new vulnerability was detected |
| `vulnerability.resolved` | A vulnerability was resolved |
| `aegis.activity` | AI agent action or recommendation |
| `administrative.member_added` | A member was added to the org |
| `administrative.settings_changed` | Organization settings were modified |

### Payload format

```json
{
  "event": "vulnerability.found",
  "timestamp": "2026-02-25T12:00:00Z",
  "organization_id": "uuid",
  "data": {
    "vulnerability_id": "CVE-2026-XXXX",
    "severity": "critical",
    "package": "lodash",
    "version": "4.17.20",
    "project": "my-project"
  }
}
```

---

## Testing

### Testing OAuth flows locally

1. Set up your provider's OAuth app with `http://localhost:3001` as the redirect base URL
2. Set the required env vars (`YOURPROVIDER_CLIENT_ID`, `YOURPROVIDER_CLIENT_SECRET`)
3. Start the backend (`npm run dev` in `backend/`)
4. Navigate to an organization's Settings → Integrations
5. Click "Add YourProvider" and complete the OAuth flow
6. Verify the connection appears in the table

### Testing custom webhooks

1. Use a service like [webhook.site](https://webhook.site) to get a test URL
2. Create a custom integration with that URL
3. Copy the signing secret
4. Trigger an event and verify the POST arrives at your test URL
5. Verify the `X-Deptex-Signature` header matches the expected HMAC

### Verifying database state

```sql
SELECT id, provider, display_name, status, metadata
FROM organization_integrations
WHERE organization_id = 'your-org-id'
ORDER BY created_at;
```
