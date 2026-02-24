import * as fs from 'fs';
import * as path from 'path';

export interface DetectedScript {
  stage: 'preinstall' | 'install' | 'postinstall';
  command: string;
}

export interface ScriptCapabilitiesResult {
  status: 'pass' | 'warning' | 'fail';
  detectedScripts: DetectedScript[];
  hasNetworkAccess: boolean;
  hasShellExecution: boolean;
  hasDangerousPatterns: boolean;
  dangerousPatterns: string[];
}

// Patterns that indicate network access
const NETWORK_PATTERNS = [
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bfetch\b/i,
  /\bhttp[s]?:\/\//i,
  /\baxios\b/i,
  /\brequest\b/i,
  /\bnode-fetch\b/i,
  /\bsocket\b/i,
  /\bnet\./i,
  /\bdns\./i,
];

// Patterns that indicate shell execution
const SHELL_PATTERNS = [
  /\bsh\s+-c\b/i,
  /\bbash\s+-c\b/i,
  /\bexec\b/i,
  /\bspawn\b/i,
  /\bchild_process\b/i,
  /\beval\b/i,
  /\`.*\`/, // Backtick command execution
  /\$\(.*\)/, // $(command) execution
];

// Dangerous patterns that warrant immediate attention
const DANGEROUS_PATTERNS = [
  { pattern: /\brm\s+-rf\b/i, name: 'Recursive file deletion (rm -rf)' },
  { pattern: /\bchmod\b.*777/i, name: 'Setting full permissions (chmod 777)' },
  { pattern: /\bsudo\b/i, name: 'Superuser access (sudo)' },
  { pattern: /\/etc\/passwd/i, name: 'Accessing /etc/passwd' },
  { pattern: /\/etc\/shadow/i, name: 'Accessing /etc/shadow' },
  { pattern: /\benv\b.*\bsecret\b/i, name: 'Accessing environment secrets' },
  { pattern: /\bprocess\.env\b/i, name: 'Accessing process environment variables' },
  { pattern: /\bbase64\s+-d\b/i, name: 'Base64 decoding (potential obfuscation)' },
  { pattern: /\bpowershell\b/i, name: 'PowerShell execution' },
  { pattern: /\bcmd\s+\/c\b/i, name: 'Windows command execution' },
  { pattern: /\beval\s*\(/i, name: 'Dynamic code evaluation (eval)' },
  { pattern: /\bFunction\s*\(/i, name: 'Dynamic function creation' },
  { pattern: /\\x[0-9a-fA-F]{2}/i, name: 'Hex-encoded content' },
  { pattern: /\\u[0-9a-fA-F]{4}/i, name: 'Unicode-encoded content' },
];

/**
 * Analyze script capabilities in package.json
 * 
 * Checks for:
 * - preinstall, install, postinstall lifecycle hooks
 * - Network access patterns
 * - Shell execution patterns
 * - Dangerous patterns
 */
export function analyzeScriptCapabilities(npmDir: string): ScriptCapabilitiesResult {
  console.log(`[${new Date().toISOString()}] 🔍 Analyzing script capabilities...`);

  const detectedScripts: DetectedScript[] = [];
  let hasNetworkAccess = false;
  let hasShellExecution = false;
  const dangerousPatterns: string[] = [];

  try {
    // Read package.json from npm tarball
    const packageJsonPath = path.join(npmDir, 'package.json');

    if (!fs.existsSync(packageJsonPath)) {
      console.log(`[${new Date().toISOString()}] ⚠️ No package.json found in ${npmDir}`);
      return {
        status: 'warning',
        detectedScripts: [],
        hasNetworkAccess: false,
        hasShellExecution: false,
        hasDangerousPatterns: false,
        dangerousPatterns: [],
      };
    }

    const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'));
    const scripts = packageJson.scripts || {};

    // Check for lifecycle hooks
    const lifecycleHooks: Array<'preinstall' | 'install' | 'postinstall'> = [
      'preinstall',
      'install',
      'postinstall',
    ];

    for (const hook of lifecycleHooks) {
      if (scripts[hook]) {
        const command = scripts[hook];
        detectedScripts.push({
          stage: hook,
          command,
        });

        // Check for network access
        for (const pattern of NETWORK_PATTERNS) {
          if (pattern.test(command)) {
            hasNetworkAccess = true;
            break;
          }
        }

        // Check for shell execution
        for (const pattern of SHELL_PATTERNS) {
          if (pattern.test(command)) {
            hasShellExecution = true;
            break;
          }
        }

        // Check for dangerous patterns
        for (const { pattern, name } of DANGEROUS_PATTERNS) {
          if (pattern.test(command)) {
            if (!dangerousPatterns.includes(name)) {
              dangerousPatterns.push(name);
            }
          }
        }
      }
    }

    // Also check for prepare script (runs after install)
    if (scripts.prepare) {
      // Check prepare script for suspicious patterns but don't count as lifecycle hook
      const command = scripts.prepare;

      for (const pattern of NETWORK_PATTERNS) {
        if (pattern.test(command)) {
          hasNetworkAccess = true;
          break;
        }
      }

      for (const { pattern, name } of DANGEROUS_PATTERNS) {
        if (pattern.test(command)) {
          if (!dangerousPatterns.includes(name)) {
            dangerousPatterns.push(name);
          }
        }
      }
    }

    // Determine status
    let status: 'pass' | 'warning' | 'fail' = 'pass';

    if (dangerousPatterns.length > 0 || (hasNetworkAccess && hasShellExecution)) {
      status = 'fail';
    } else if (detectedScripts.length > 0) {
      // Has lifecycle scripts - check if they look safe
      const safePatterns = [
        /^node\s+/i, // node script.js
        /^npm\s+run\s+/i, // npm run build
        /^tsc\b/i, // TypeScript compilation
        /^babel\b/i, // Babel transpilation
        /^webpack\b/i, // Webpack bundling
        /^rollup\b/i, // Rollup bundling
        /^esbuild\b/i, // esbuild bundling
        /^husky\b/i, // Husky git hooks
        /^patch-package\b/i, // patch-package
        /^ngcc\b/i, // Angular compiler
        /^prisma\s+generate/i, // Prisma client generation
        /^node-gyp\b/i, // Native module compilation
        /^node-pre-gyp\b/i, // Native module pre-built binaries
        /^prebuild-install\b/i, // Pre-built native binaries
        /^cmake-js\b/i, // CMake-based native builds
      ];

      const allScriptsSafe = detectedScripts.every(s =>
        safePatterns.some(p => p.test(s.command))
      );

      status = allScriptsSafe ? 'warning' : 'fail';
    }

    console.log(`[${new Date().toISOString()}] 📊 Script capabilities: ${status} (${detectedScripts.length} lifecycle scripts)`);

    return {
      status,
      detectedScripts,
      hasNetworkAccess,
      hasShellExecution,
      hasDangerousPatterns: dangerousPatterns.length > 0,
      dangerousPatterns,
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Script analysis failed:`, error.message);
    return {
      status: 'warning',
      detectedScripts: [],
      hasNetworkAccess: false,
      hasShellExecution: false,
      hasDangerousPatterns: false,
      dangerousPatterns: [],
    };
  }
}
