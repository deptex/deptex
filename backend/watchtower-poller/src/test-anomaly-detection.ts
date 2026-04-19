/**
 * Test script for Anomaly Detection Feature
 * 
 * Tests the anomaly detector with synthetic commit data to verify:
 * 1. Graduated scoring produces varied point values (not just multiples of 5)
 * 2. Each detection factor triggers correctly
 * 3. Reasons are descriptive and helpful
 * 
 * Run with: npx tsx src/test-anomaly-detection.ts
 */

import { calculateAnomalyScore, calculateAnomaliesForCommits } from './anomaly-detection';
import { CommitDetails } from './incremental-analyzer';
import { ContributorProfile, AnomalyResult } from './storage';

interface TestCase {
    name: string;
    description: string;
    commit: CommitDetails;
    profile: ContributorProfile;
    expectedMinScore: number;
    expectedMaxScore: number;
    expectedFactors: string[];
}

/**
 * Create a baseline contributor profile for testing
 */
function createBaselineProfile(overrides: Partial<ContributorProfile> = {}): ContributorProfile {
    return {
        id: 'test-contributor-id',
        authorEmail: 'developer@example.com',
        authorName: 'Regular Developer',
        totalCommits: 50,
        avgLinesAdded: 100,
        avgLinesDeleted: 30,
        avgFilesChanged: 3,
        stddevLinesAdded: 50,
        stddevLinesDeleted: 20,
        stddevFilesChanged: 2,
        avgCommitMessageLength: 50,
        stddevCommitMessageLength: 20,
        insertToDeleteRatio: 3.0,
        commitTimeHistogram: {
            '9:00': 10,
            '10:00': 15,
            '11:00': 12,
            '14:00': 10,
            '15:00': 8,
            '16:00': 5,
            '3:00': 0,
            '4:00': 0,
        },
        typicalDaysActive: {
            'Monday': 12,
            'Tuesday': 15,
            'Wednesday': 13,
            'Thursday': 10,
            'Friday': 8,
            'Saturday': 1,
            'Sunday': 1,
        },
        commitTimeHeatmap: [],
        filesWorkedOn: {
            'src/index.ts': 20,
            'src/utils.ts': 15,
            'src/config.ts': 10,
            'README.md': 5,
        },
        firstCommitDate: new Date('2023-01-01'),
        lastCommitDate: new Date('2026-01-28'),
        ...overrides,
    };
}

/**
 * Create a commit for testing
 */
function createTestCommit(overrides: Partial<CommitDetails> = {}): CommitDetails {
    return {
        sha: 'abc123def456',
        authorName: 'Regular Developer',
        authorEmail: 'developer@example.com',
        message: 'chore: update dependencies',
        timestamp: new Date('2026-01-29T10:30:00'), // Wednesday 10:30 AM - normal time
        linesAdded: 50,
        linesDeleted: 20,
        filesChanged: 2,
        diffData: {
            filesChanged: ['src/utils.ts', 'README.md'],
        },
        ...overrides,
    };
}

/**
 * Run a single test case
 */
function runTest(testCase: TestCase): { passed: boolean; result: AnomalyResult; notes: string } {
    const result = calculateAnomalyScore(testCase.commit, testCase.profile);

    const scoreInRange = result.totalScore >= testCase.expectedMinScore &&
        result.totalScore <= testCase.expectedMaxScore;

    const foundFactors = result.breakdown.map(b => b.factor);
    const hasExpectedFactors = testCase.expectedFactors.every(f => foundFactors.includes(f));

    const passed = scoreInRange && hasExpectedFactors;

    let notes = '';
    if (!scoreInRange) {
        notes += `Score ${result.totalScore} outside expected range [${testCase.expectedMinScore}, ${testCase.expectedMaxScore}]. `;
    }
    if (!hasExpectedFactors) {
        const missing = testCase.expectedFactors.filter(f => !foundFactors.includes(f));
        notes += `Missing expected factors: ${missing.join(', ')}. `;
    }

    return { passed, result, notes: notes || 'All checks passed' };
}

/**
 * Print test result
 */
function printResult(testCase: TestCase, outcome: { passed: boolean; result: AnomalyResult; notes: string }): void {
    const emoji = outcome.passed ? '✅' : '❌';
    console.log(`\n${'='.repeat(60)}`);
    console.log(`${emoji} ${testCase.name}`);
    console.log(`${'='.repeat(60)}`);
    console.log(`Description: ${testCase.description}`);
    console.log(`Expected Score Range: ${testCase.expectedMinScore} - ${testCase.expectedMaxScore}`);
    console.log(`Actual Score: ${outcome.result.totalScore}`);
    console.log(`Expected Factors: ${testCase.expectedFactors.join(', ') || '(none)'}`);
    console.log(`\nBreakdown:`);

    if (outcome.result.breakdown.length === 0) {
        console.log('  (no anomalies detected)');
    } else {
        for (const item of outcome.result.breakdown) {
            console.log(`  • ${item.factor}: ${item.points} pts`);
            console.log(`    ${item.reason}`);
        }
    }

    console.log(`\nResult: ${outcome.notes}`);
}

/**
 * Define all test cases
 */
function getTestCases(): TestCase[] {
    return [
        // Test 1: Normal commit - should have low/zero score
        {
            name: 'TEST 1: Normal Commit',
            description: 'Regular commit by established contributor during normal hours',
            commit: createTestCommit(),
            profile: createBaselineProfile(),
            expectedMinScore: 0,
            expectedMaxScore: 5,
            expectedFactors: [],
        },

        // Test 2: Large commit - should trigger files/lines changed
        {
            name: 'TEST 2: Large Commit',
            description: 'Commit with unusually high file and line counts',
            commit: createTestCommit({
                filesChanged: 25,
                linesAdded: 2000,
                linesDeleted: 500,
                diffData: { filesChanged: ['src/a.ts', 'src/b.ts', 'src/c.ts'] },
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 30, // 15 + 15 + new_files
            expectedMaxScore: 70,
            expectedFactors: ['files_changed', 'lines_changed'],
        },

        // Test 3: Security-sensitive files - package.json modification
        {
            name: 'TEST 3: Security-Sensitive File (package.json)',
            description: 'Commit modifying package.json - critical supply chain file',
            commit: createTestCommit({
                diffData: { filesChanged: ['package.json', 'src/utils.ts'] },
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 15,
            expectedMaxScore: 25,
            expectedFactors: ['security_sensitive_files'],
        },

        // Test 4: First-time contributor
        {
            name: 'TEST 4: First-Time Contributor',
            description: 'Commit from new contributor with only 1 commit',
            commit: createTestCommit({
                authorEmail: 'newbie@example.com',
                authorName: 'New Contributor',
            }),
            profile: createBaselineProfile({
                authorEmail: 'newbie@example.com',
                authorName: 'New Contributor',
                totalCommits: 1,
            }),
            expectedMinScore: 8,
            expectedMaxScore: 15,
            expectedFactors: ['first_time_contributor'],
        },

        // Test 5: Unusual timing
        {
            name: 'TEST 5: Unusual Commit Time',
            description: 'Commit at 3 AM when contributor never works',
            commit: createTestCommit({
                timestamp: new Date('2026-01-29T03:30:00'), // 3:30 AM
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 5,
            expectedMaxScore: 10,
            expectedFactors: ['abnormal_time'],
        },

        // Test 6: Unusual day
        {
            name: 'TEST 6: Unusual Commit Day',
            description: 'Commit on Saturday when contributor rarely works weekends',
            commit: createTestCommit({
                timestamp: new Date('2026-01-31T10:30:00'), // Saturday
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 4,
            expectedMaxScore: 10,
            expectedFactors: ['abnormal_day'],
        },

        // Test 7: Sensitive keywords in message
        {
            name: 'TEST 7: Sensitive Keywords (High Severity)',
            description: 'Commit message contains "password" and "secret"',
            commit: createTestCommit({
                message: 'fix: update password encryption using secret key',
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 12,
            expectedMaxScore: 20,
            expectedFactors: ['sensitive_keywords'],
        },

        // Test 8: Medium severity keywords
        {
            name: 'TEST 8: Sensitive Keywords (Medium Severity)',
            description: 'Commit message contains auth-related terms',
            commit: createTestCommit({
                message: 'feat: add token refresh for auth flow',
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 3,
            expectedMaxScore: 8,
            expectedFactors: ['sensitive_keywords'],
        },

        // Test 9: New files never worked on
        {
            name: 'TEST 9: Working on New Files',
            description: 'Contributor touches files they have never modified before',
            commit: createTestCommit({
                diffData: { filesChanged: ['src/brand-new.ts', 'lib/never-touched.ts', 'core/unknown.ts'] },
            }),
            profile: createBaselineProfile(),
            expectedMinScore: 30,
            expectedMaxScore: 40,
            expectedFactors: ['new_files'],
        },

        // Test 10: Unusual message length
        {
            name: 'TEST 10: Unusual Message Length',
            description: 'Extremely long commit message (potential obfuscation)',
            commit: createTestCommit({
                message: 'x'.repeat(500), // Very long message
            }),
            profile: createBaselineProfile({
                avgCommitMessageLength: 50,
                stddevCommitMessageLength: 20,
            }),
            expectedMinScore: 5,
            expectedMaxScore: 12,
            expectedFactors: ['message_length'],
        },

        // Test 11: Unusual insert/delete ratio
        {
            name: 'TEST 11: Unusual Insert/Delete Ratio',
            description: 'Commit has drastically different ratio than usual',
            commit: createTestCommit({
                linesAdded: 10,
                linesDeleted: 500, // Usually adds more than deletes
            }),
            profile: createBaselineProfile({
                insertToDeleteRatio: 3.0, // Usually 3:1 add:delete
            }),
            expectedMinScore: 3,
            expectedMaxScore: 25, // May also trigger lines_changed due to high deletions
            expectedFactors: ['insert_delete_ratio'],
        },

        // Test 12: Combined anomalies (red team scenario)
        {
            name: 'TEST 12: Combined Anomalies (Red Team Scenario)',
            description: 'New contributor, modifying package.json, at 3 AM, with sensitive keywords',
            commit: createTestCommit({
                authorEmail: 'suspicious@attacker.com',
                message: 'chore: update dependencies with new secret token handling',
                timestamp: new Date('2026-01-26T03:30:00'), // Sunday 3 AM
                diffData: { filesChanged: ['package.json', 'src/auth.ts', 'src/new-module.ts'] },
            }),
            profile: createBaselineProfile({
                authorEmail: 'suspicious@attacker.com',
                totalCommits: 1,
            }),
            expectedMinScore: 40,
            expectedMaxScore: 80,
            expectedFactors: ['first_time_contributor', 'security_sensitive_files', 'sensitive_keywords', 'abnormal_time'],
        },

        // Test 13: Verify non-5 point values
        {
            name: 'TEST 13: Graduated Scoring Verification',
            description: 'Commit that should produce non-multiples-of-5 score',
            commit: createTestCommit({
                filesChanged: 8, // Should be 1.5-2 std dev -> 6 points
                message: 'feat: add auth token validation', // auth -> 3 points
            }),
            profile: createBaselineProfile({
                avgFilesChanged: 3,
                stddevFilesChanged: 2, // 8 files = 2.5 std dev
            }),
            expectedMinScore: 6, // At least 6 from files
            expectedMaxScore: 20,
            expectedFactors: ['files_changed'],
        },
    ];
}

/**
 * Main test runner
 */
async function runTests(): Promise<void> {
    console.log('\n' + '='.repeat(60));
    console.log('🔬 ANOMALY DETECTION TEST SUITE');
    console.log('='.repeat(60));
    console.log('Testing the Watchtower Anomaly Detector');
    console.log('Verifies graduated scoring and new detection factors');
    console.log('');

    const testCases = getTestCases();
    const results: { testCase: TestCase; outcome: ReturnType<typeof runTest> }[] = [];

    for (const testCase of testCases) {
        const outcome = runTest(testCase);
        results.push({ testCase, outcome });
        printResult(testCase, outcome);
    }

    // Print summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(60));

    const passed = results.filter(r => r.outcome.passed).length;
    const failed = results.filter(r => !r.outcome.passed).length;

    // Collect unique scores to verify variation
    const uniqueScores = new Set(results.map(r => r.outcome.result.totalScore));
    const nonMultiplesOf5 = Array.from(uniqueScores).filter(s => s % 5 !== 0);

    console.log(`\nTest Results: ${passed}/${results.length} passed`);
    console.log(`\nUnique Scores Generated: ${Array.from(uniqueScores).sort((a, b) => a - b).join(', ')}`);
    console.log(`Non-multiples-of-5 Scores: ${nonMultiplesOf5.join(', ') || '(none)'}`);

    if (nonMultiplesOf5.length > 0) {
        console.log('\n✅ SUCCESS: Scoring now produces varied point values!');
    } else {
        console.log('\n⚠️ WARNING: All scores are still multiples of 5');
    }

    // List failed tests
    if (failed > 0) {
        console.log('\n❌ Failed Tests:');
        for (const r of results.filter(r => !r.outcome.passed)) {
            console.log(`  • ${r.testCase.name}: ${r.outcome.notes}`);
        }
    }

    console.log('\n' + '='.repeat(60));
    if (passed === results.length && nonMultiplesOf5.length > 0) {
        console.log('🎉 ALL TESTS PASSED! Anomaly detection improvements working correctly.');
    } else if (passed === results.length) {
        console.log('⚠️ Tests passed but scoring variation may need review.');
    } else {
        console.log('❌ SOME TESTS FAILED. Please review the results above.');
    }
    console.log('='.repeat(60) + '\n');
}

// Run the tests
runTests().catch(console.error);
