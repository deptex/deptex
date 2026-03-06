# GitHub App webhooks: why you might only see check_suite

Deptex receives GitHub webhooks at a single endpoint. **Which events you get is determined by the GitHub App configuration on GitHub**, not by our code. If you only see `check_suite` in the Webhooks screen and no push or pull_request events, the app is not subscribed to those events.

## There is no "commit" webhook

GitHub does **not** send a separate "commit" or "commits" webhook. Commit data is delivered inside the **push** event payload (`payload.commits`, `payload.head_commit`, etc.). So:

- **Push** = branch update; payload includes commits, ref, repository, sender.
- **Pull request** = PR opened/updated/closed; payload includes PR metadata, diff URLs, etc.
- **Check suite** = CI/checks lifecycle (requested, completed, rerequested); sent when the app has Checks permission.

If you don’t subscribe to **Push**, you will never receive commit data via webhooks.

## Why you might only get check_suite

1. **Checks permission**  
   If your GitHub App has **Checks** (read or write), GitHub **automatically** subscribes it to `check_suite` (and often `check_run`). So you’ll see those without doing anything else.

2. **Push and Pull request are opt-in**  
   **Push** and **Pull requests** are separate checkboxes under "Subscribe to events". If they weren’t selected when the app was created (or in a later edit), GitHub will not send those events to your webhook URL. You’ll only get events you subscribed to (e.g. check_suite).

## How to get push and pull_request events

1. Go to **GitHub** → **Settings** → **Developer settings** → **GitHub Apps** → select your Deptex app (or create one).
2. Under **Permissions and events**:
   - **Repository permissions**: ensure you have at least the permissions your app needs (e.g. Contents, Metadata, Pull requests if you use them).
   - **Subscribe to events**: enable:
     - **Push**
     - **Pull requests**
     - (Optional) **Check suite** / **Check run** can stay enabled if you want to keep seeing them.)
3. Save. New installations (and often existing ones) will then receive push and pull_request to your webhook URL.

If the app is already installed on orgs/repos, you may need to have users **reinstall or update the app** (e.g. from the app’s installation settings) so that the new event subscriptions take effect for their installations.

## What we do with each event

| Event           | Deptex behavior |
|----------------|------------------|
| **push**       | Used for sync: detect manifest/lockfile changes, optionally queue extraction, record commits. |
| **pull_request** | Used for PR checks: run policy/guardrails, post check run and comment. |
| **check_suite** | Recorded for audit only; we do not run sync or PR checks from it. |
| **installation** / **installation_repositories** / **repository** | Used for app install/uninstall and repo lifecycle. |

Our handler records every delivery (so check_suite appears in the Webhooks screen) but only **push** and **pull_request** drive sync and PR checks.
