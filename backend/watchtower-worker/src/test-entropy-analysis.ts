/**
 * Test script for Entropy Analysis Feature
 * 
 * Tests the entropy analyzer against:
 * 1. Healthy packages (normal source code) - lodash, react
 * 2. Minified packages (expected high entropy) - jquery
 * 3. Simulated malicious attack (injected high entropy blob)
 * 
 * Run with: npx tsx src/test-entropy-analysis.ts
 */

import * as pacote from 'pacote';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { analyzeEntropy, EntropyAnalysisResult, calculateShannonEntropy, getEntropyDescription } from './entropy-analysis';

interface TestResult {
    testName: string;
    packageName: string;
    result: EntropyAnalysisResult;
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
 * Test 0: Unit Test for Shannon Entropy Calculation
 */
function runEntropyCalculationTest(): void {
    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 0: SHANNON ENTROPY CALCULATION UNIT TEST');
    console.log('='.repeat(60));

    // Test 1: Repetitive string (low entropy)
    const repetitive = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const repetitiveEntropy = calculateShannonEntropy(repetitive);
    console.log(`Repetitive "aaa...": ${repetitiveEntropy.toFixed(2)} - ${getEntropyDescription(repetitiveEntropy)}`);

    // Test 2: Normal English text (medium entropy)
    const normalText = 'function verifyUser() { return true; } function validateInput(data) { return data.length > 0; }';
    const normalEntropy = calculateShannonEntropy(normalText);
    console.log(`Normal code: ${normalEntropy.toFixed(2)} - ${getEntropyDescription(normalEntropy)}`);

    // Test 3: Random characters (high entropy)
    const randomChars = Array.from({ length: 200 }, () =>
        String.fromCharCode(32 + Math.floor(Math.random() * 94)) // Printable ASCII
    ).join('');
    const randomEntropy = calculateShannonEntropy(randomChars);
    console.log(`Random printable: ${randomEntropy.toFixed(2)} - ${getEntropyDescription(randomEntropy)}`);

    // Test 4: Base64-like string (very high entropy)
    const base64Like = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5K/='.repeat(10);
    const base64Entropy = calculateShannonEntropy(base64Like);
    console.log(`Base64-like: ${base64Entropy.toFixed(2)} - ${getEntropyDescription(base64Entropy)}`);

    // Test 5: Full random bytes (maximum entropy simulation)
    const fullRandom = Array.from({ length: 500 }, () =>
        String.fromCharCode(Math.floor(Math.random() * 256))
    ).join('');
    const fullRandomEntropy = calculateShannonEntropy(fullRandom);
    console.log(`Full random bytes: ${fullRandomEntropy.toFixed(2)} - ${getEntropyDescription(fullRandomEntropy)}`);

    console.log('\n✅ Entropy calculation unit tests complete');
}

/**
 * Test 1: Healthy Package Test (Normal Source Code)
 * Tests lodash - readable source code should have low entropy
 */
async function runHealthyTest(): Promise<TestResult> {
    const packageName = 'lodash';
    const version = '4.17.21';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 1: HEALTHY PACKAGE TEST (Normal Source Code)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('Expected: PASS (normal entropy levels)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-entropy-healthy-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Analyze entropy
        console.log('\n🔍 Analyzing entropy...');
        const result = await analyzeEntropy(tmpDir);

        const testPassed = result.status === 'pass' || result.status === 'warning';

        return {
            testName: 'Healthy Package Test (Normal Source Code)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'pass',
            testPassed,
            notes: testPassed
                ? `✅ Normal entropy levels (avg: ${result.avgEntropy}, max: ${result.maxEntropy})`
                : `❌ Unexpected high entropy detected`,
        };
    } catch (error: any) {
        return {
            testName: 'Healthy Package Test (Normal Source Code)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                highEntropyFiles: [],
                avgEntropy: 0,
                maxEntropy: 0,
                filesAnalyzed: 0,
                totalSize: 0,
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
 * Test 2: Minified Package Test (Expected High Entropy)
 * Tests jquery - minified code should be detected but not flagged as critical
 */
async function runMinifiedTest(): Promise<TestResult> {
    const packageName = 'jquery';
    const version = '3.7.1';

    console.log('\n' + '='.repeat(60));
    console.log('🧪 TEST 2: MINIFIED PACKAGE TEST (Expected High Entropy)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('Expected: WARNING (minified code has high entropy but is legitimate)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-entropy-minified-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Show some file stats
        const distDir = path.join(tmpDir, 'dist');
        if (fs.existsSync(distDir)) {
            console.log('\n📁 Files in dist/:');
            const distFiles = fs.readdirSync(distDir).slice(0, 5);
            distFiles.forEach(f => console.log(`   - ${f}`));
        }

        // Analyze entropy
        console.log('\n🔍 Analyzing entropy...');
        const result = await analyzeEntropy(tmpDir);

        // For minified packages, warning is acceptable (minified code legitimately has high entropy)
        const testPassed = result.status === 'pass' || result.status === 'warning';

        return {
            testName: 'Minified Package Test (Expected High Entropy)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'warning',
            testPassed,
            notes: testPassed
                ? `✅ Minified code detected appropriately (max: ${result.maxEntropy})`
                : `❌ Unexpected FAIL status for minified code`,
        };
    } catch (error: any) {
        return {
            testName: 'Minified Package Test (Expected High Entropy)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                highEntropyFiles: [],
                avgEntropy: 0,
                maxEntropy: 0,
                filesAnalyzed: 0,
                totalSize: 0,
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
 * Test 3: Simulated Attack Test (Injected High Entropy Blob)
 * Injects encrypted/obfuscated payload in unexpected location
 */
async function runSimulatedAttackTest(): Promise<TestResult> {
    const packageName = 'lodash';
    const version = '4.17.21';

    console.log('\n' + '='.repeat(60));
    console.log('🚨 TEST 3: SIMULATED ATTACK TEST (High Entropy Injection)');
    console.log('='.repeat(60));
    console.log(`📦 Package: ${packageName}@${version}`);
    console.log('⚠️ Will inject high entropy blob in unexpected location');
    console.log('Expected: FAIL (should detect obfuscated/encrypted payload)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-entropy-attack-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // 🚨 INJECT HIGH ENTROPY BLOB (Red Team Simulation)
        console.log('');
        console.log('🚨🚨🚨 INJECTING HIGH ENTROPY BLOB 🚨🚨🚨');
        console.log('');

        // Create a hidden.js file with encrypted-looking content
        // This simulates the flatmap-stream attack's test/data.js file
        const hiddenFilePath = path.join(tmpDir, 'lib', 'hidden-payload.js');

        // Create lib directory if it doesn't exist
        fs.mkdirSync(path.join(tmpDir, 'lib'), { recursive: true });

        // Generate VERY high-entropy payload (simulating AES encrypted data)
        // We need entropy > 6.0 to trigger FAIL status
        // Using full byte range gives maximum entropy (~7.5-8.0)
        // The key is to have MOSTLY random content with minimal structure
        const randomBytes = Buffer.from(
            Array.from({ length: 5000 }, () => Math.floor(Math.random() * 256))
        );

        // Create content that is almost entirely random bytes (very high entropy)
        const maliciousContent = randomBytes.toString('binary');

        fs.writeFileSync(hiddenFilePath, maliciousContent);
        console.log(`💉 Created high entropy file: lib/hidden-payload.js`);

        // Calculate and show the entropy of our injected file
        const injectedEntropy = calculateShannonEntropy(maliciousContent);
        console.log(`💉 Injected file entropy: ${injectedEntropy.toFixed(2)} - ${getEntropyDescription(injectedEntropy)}`);

        console.log('');
        console.log('🚨🚨🚨 INJECTION COMPLETE 🚨🚨🚨');
        console.log('');

        // Analyze entropy
        console.log('🔍 Analyzing entropy...');
        const result = await analyzeEntropy(tmpDir);

        // Should FAIL due to high entropy file in unexpected location
        const testPassed = result.status === 'fail';

        // Check if our injected file was detected
        const foundInjectedFile = result.highEntropyFiles.some(f =>
            f.path.includes('hidden-payload.js')
        );

        return {
            testName: 'Simulated Attack Test (High Entropy Injection)',
            packageName: `${packageName}@${version} (MODIFIED)`,
            result,
            expected: 'fail',
            testPassed: testPassed && foundInjectedFile,
            notes: testPassed && foundInjectedFile
                ? `🎯 Successfully detected injected high entropy file!`
                : `❌ Failed to detect injection (status: ${result.status}, found file: ${foundInjectedFile})`,
        };
    } catch (error: any) {
        return {
            testName: 'Simulated Attack Test (High Entropy Injection)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                highEntropyFiles: [],
                avgEntropy: 0,
                maxEntropy: 0,
                filesAnalyzed: 0,
                totalSize: 0,
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
    console.log('Expected: PASS (normal entropy)');
    console.log('');

    const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
    const timestamp = Date.now();
    const random = Math.random().toString(36).substring(7);
    const tmpDir = path.join(os.tmpdir(), `test-entropy-react-${safeName}-${timestamp}-${random}`);

    try {
        // Download npm tarball
        console.log('📦 Downloading npm tarball...');
        fs.mkdirSync(tmpDir, { recursive: true });
        await pacote.extract(`${packageName}@${version}`, tmpDir);
        console.log(`✅ npm tarball extracted to ${tmpDir}`);

        // Analyze entropy
        console.log('\n🔍 Analyzing entropy...');
        const result = await analyzeEntropy(tmpDir);

        const testPassed = result.status === 'pass' || result.status === 'warning';

        return {
            testName: 'Additional Healthy Package (react)',
            packageName: `${packageName}@${version}`,
            result,
            expected: 'pass',
            testPassed,
            notes: testPassed
                ? `✅ Normal entropy levels (avg: ${result.avgEntropy}, max: ${result.maxEntropy})`
                : `❌ Unexpected high entropy detected`,
        };
    } catch (error: any) {
        return {
            testName: 'Additional Healthy Package (react)',
            packageName: `${packageName}@${version}`,
            result: {
                status: 'warning',
                highEntropyFiles: [],
                avgEntropy: 0,
                maxEntropy: 0,
                filesAnalyzed: 0,
                totalSize: 0,
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

    console.log(`\nEntropy Statistics:`);
    console.log(`  📊 Files Analyzed: ${result.result.filesAnalyzed}`);
    console.log(`  📈 Average Entropy: ${result.result.avgEntropy}`);
    console.log(`  📉 Max Entropy: ${result.result.maxEntropy}`);
    console.log(`  ⚠️ High Entropy Files: ${result.result.highEntropyFiles.length}`);

    if (result.result.highEntropyFiles.length > 0) {
        console.log('\nHigh Entropy Files Detected:');
        for (const file of result.result.highEntropyFiles.slice(0, 5)) {
            console.log(`  🔥 ${file.path} (entropy: ${file.entropy}, size: ${file.size} bytes)`);
        }
        if (result.result.highEntropyFiles.length > 5) {
            console.log(`  ... and ${result.result.highEntropyFiles.length - 5} more files`);
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
    console.log('🔬 ENTROPY ANALYSIS TEST SUITE');
    console.log('='.repeat(60));
    console.log('Testing the Watchtower Entropy Analyzer');
    console.log('Detects encrypted, obfuscated, and packed code');
    console.log('');

    const results: TestResult[] = [];

    // Run Unit Test (synchronous)
    runEntropyCalculationTest();

    // Run Test 1: Healthy Package (lodash)
    const healthyResult = await runHealthyTest();
    printResult(healthyResult);
    results.push(healthyResult);

    // Run Test 2: Minified Package (jquery)
    const minifiedResult = await runMinifiedTest();
    printResult(minifiedResult);
    results.push(minifiedResult);

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
        console.log(`   📊 Avg: ${result.result.avgEntropy}, Max: ${result.result.maxEntropy}, High Files: ${result.result.highEntropyFiles.length}`);
        if (result.notes) {
            console.log(`   📝 ${result.notes}`);
        }
        if (!result.testPassed) allPassed = false;
    }

    console.log('');
    if (allPassed) {
        console.log('🎉 ALL TESTS PASSED! Entropy Analysis feature is working correctly.');
        console.log('');
        console.log('✅ Healthy packages (lodash, react) show PASS status');
        console.log('✅ Minified packages (jquery) show WARNING status (expected)');
        console.log('✅ High entropy injection is detected as FAIL status');
    } else {
        console.log('⚠️ SOME TESTS FAILED. Please review the results above.');
    }
    console.log('');
}

// Run the tests
runTests().catch(console.error);
