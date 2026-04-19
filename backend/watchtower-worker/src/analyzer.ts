import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import simpleGit from 'simple-git';
import { FullAnalysisResults } from './storage';
import { parseRepositoryUrl, cloneRepository, cleanupRepository } from './github';
import { extractCommitsFromRepo, CommitDetails } from './commit-extractor';
import { buildContributorProfiles, ContributorProfile } from './contributor-profile';
import { calculateAnomaliesForCommits, AnomalyResult } from './anomaly-detection';
import { checkRegistryIntegrity, RegistryIntegrityResult } from './registry-integrity';
import { analyzeScriptCapabilities, ScriptCapabilitiesResult } from './script-capabilities';
import { analyzeEntropy, EntropyAnalysisResult } from './entropy-analysis';

export interface AnalysisOutput {
  success: boolean;
  data?: FullAnalysisResults;
  tmpDir?: string; // Path to temp directory for cleanup
  error?: string;
  // Additional data for database storage
  commits?: CommitDetails[];
  contributors?: ContributorProfile[];
  anomalies?: AnomalyResult[];
}

/**
 * Create a unique temp directory for this analysis
 */
function createTempDir(packageName: string): string {
  const safeName = packageName.replace(/[^a-zA-Z0-9-_]/g, '-');
  const timestamp = Date.now();
  const random = Math.random().toString(36).substring(7);
  const tmpDir = path.join(os.tmpdir(), `watchtower-${safeName}-${timestamp}-${random}`);
  fs.mkdirSync(tmpDir, { recursive: true });
  return tmpDir;
}

/**
 * Clean up temporary directory
 */
export function cleanupTempDir(tmpDir: string): void {
  try {
    if (fs.existsSync(tmpDir)) {
      console.log(`[${new Date().toISOString()}] 🧹 Cleaning up temp directory: ${tmpDir}`);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  } catch (error) {
    console.warn(`Failed to cleanup temp directory ${tmpDir}:`, error);
  }
}

/**
 * Full package analysis pipeline:
 * 1. Fetch npm metadata
 * 2. Download npm tarball
 * 3. Clone git repository
 * 4. Run Registry Integrity check
 * 5. Run Script Capabilities check
 * 6. Run Entropy Analysis
 * 7. Extract commits from git repo
 * 8. Build contributor profiles
 * 9. Calculate anomaly scores
 */
export async function analyzePackage(packageName: string): Promise<AnalysisOutput> {
  const tmpDir = createTempDir(packageName);
  const npmDir = path.join(tmpDir, 'npm');
  const gitDir = path.join(tmpDir, 'git'); // For registry integrity (clones specific tag)
  const gitDirForCommits = path.join(tmpDir, 'git-commits'); // For commit analysis (clones HEAD with history)

  try {
    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] 🚀 Starting full analysis for ${packageName}`);
    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] 📁 Temp directory: ${tmpDir}`);

    // Step 1: Fetch npm metadata
    console.log(`[${new Date().toISOString()}] 📦 Step 1: Fetching npm metadata...`);
    const encodedName = encodeURIComponent(packageName);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`);

    if (!response.ok) {
      throw new Error(`npm registry returned ${response.status}`);
    }

    const packageData = await response.json() as {
      name: string;
      'dist-tags'?: { latest?: string };
      versions?: Record<string, { scripts?: Record<string, string> }>;
      time?: Record<string, string>;
      maintainers?: Array<{ name?: string; username?: string; email?: string }>;
      repository?: string | { url?: string };
    };

    // Get the latest version
    const latestVersion = packageData['dist-tags']?.latest;
    if (!latestVersion) {
      throw new Error('Could not determine latest version');
    }

    // Get version-specific data
    const versionData = packageData.versions?.[latestVersion];
    if (!versionData) {
      throw new Error(`Version ${latestVersion} not found in registry`);
    }

    // Get publish time and maintainers
    const publishedAt = packageData.time?.[latestVersion] || null;
    const maintainers = packageData.maintainers || [];

    // Get repository URL
    const rawRepository = typeof packageData.repository === 'string'
      ? packageData.repository
      : packageData.repository?.url || undefined;
    const githubUrl = parseRepositoryUrl(rawRepository);

    console.log(`[${new Date().toISOString()}] ✅ npm metadata fetched`);
    console.log(`[${new Date().toISOString()}]    - Version: ${latestVersion}`);
    console.log(`[${new Date().toISOString()}]    - Published: ${publishedAt || 'unknown'}`);
    console.log(`[${new Date().toISOString()}]    - Repository: ${rawRepository || 'none'}`);

    // Step 2-4: Registry Integrity Check (downloads tarball, clones git, compares)
    console.log(`[${new Date().toISOString()}] 🔍 Step 2-4: Registry Integrity Check...`);
    let registryIntegrity: RegistryIntegrityResult;
    try {
      registryIntegrity = await checkRegistryIntegrity(
        packageName,
        latestVersion,
        rawRepository || undefined,
        tmpDir
      );
    } catch (error: any) {
      console.warn(`[${new Date().toISOString()}] ⚠️ Registry integrity check failed: ${error.message}`);
      registryIntegrity = {
        status: 'warning',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: 0,
        gitFilesCount: 0,
        error: error.message,
      };
    }

    // Step 5: Script Capabilities Analysis
    console.log(`[${new Date().toISOString()}] 🔍 Step 5: Script Capabilities Analysis...`);
    let scriptCapabilities: ScriptCapabilitiesResult;
    try {
      scriptCapabilities = analyzeScriptCapabilities(npmDir);
    } catch (error: any) {
      console.warn(`[${new Date().toISOString()}] ⚠️ Script analysis failed: ${error.message}`);
      scriptCapabilities = {
        status: 'warning',
        detectedScripts: [],
        hasNetworkAccess: false,
        hasShellExecution: false,
        hasDangerousPatterns: false,
        dangerousPatterns: [],
      };
    }

    // Step 6: Entropy Analysis
    console.log(`[${new Date().toISOString()}] 🔍 Step 6: Entropy Analysis...`);
    let entropyAnalysis: EntropyAnalysisResult;
    try {
      entropyAnalysis = await analyzeEntropy(npmDir);
    } catch (error: any) {
      console.warn(`[${new Date().toISOString()}] ⚠️ Entropy analysis failed: ${error.message}`);
      entropyAnalysis = {
        status: 'warning',
        highEntropyFiles: [],
        avgEntropy: 0,
        maxEntropy: 0,
        filesAnalyzed: 0,
        totalSize: 0,
      };
    }

    // Steps 7-9: Commit analysis - clone repo with history for this
    let commits: CommitDetails[] = [];
    let contributors: ContributorProfile[] = [];
    let anomalies: AnomalyResult[] = [];

    // Clone repo with history for commit analysis (separate from the tag clone used for integrity check)
    if (githubUrl) {
      console.log(`[${new Date().toISOString()}] 📂 Step 7a: Cloning repo with history for commit analysis...`);
      try {
        fs.mkdirSync(gitDirForCommits, { recursive: true });
        
        // Clone with 3000 commits of history (enough for contributor profiles); we store only 500
        await simpleGit().clone(githubUrl, gitDirForCommits, [
          '--depth', '3000',
          '--single-branch',
        ]);
        console.log(`[${new Date().toISOString()}] ✅ Cloned repo with history to ${gitDirForCommits}`);
      } catch (error: any) {
        console.warn(`[${new Date().toISOString()}] ⚠️ Failed to clone repo for commit analysis: ${error.message}`);
      }
    }

    if (fs.existsSync(gitDirForCommits) && fs.existsSync(path.join(gitDirForCommits, '.git'))) {
      // Step 7: Extract commits (up to 3000 for contributor profiles; we store only 500)
      console.log(`[${new Date().toISOString()}] 🔍 Step 7b: Extracting commits...`);
      try {
        commits = await extractCommitsFromRepo(gitDirForCommits, 3000);
        console.log(`[${new Date().toISOString()}] ✅ Extracted ${commits.length} commits`);
      } catch (error: any) {
        console.warn(`[${new Date().toISOString()}] ⚠️ Commit extraction failed: ${error.message}`);
      }

      // Step 8: Build contributor profiles
      if (commits.length > 0) {
        console.log(`[${new Date().toISOString()}] 🔍 Step 8: Building contributor profiles...`);
        try {
          contributors = buildContributorProfiles(commits);
          console.log(`[${new Date().toISOString()}] ✅ Built ${contributors.length} contributor profiles`);
        } catch (error: any) {
          console.warn(`[${new Date().toISOString()}] ⚠️ Contributor profile building failed: ${error.message}`);
        }
      }

      // Step 9: Calculate anomaly scores (most recent 100 of the commits we will store)
      if (commits.length > 0 && contributors.length > 0) {
        console.log(`[${new Date().toISOString()}] 🔍 Step 9: Calculating anomaly scores...`);
        try {
          const recentCommits = commits.slice(0, 100);
          anomalies = calculateAnomaliesForCommits(recentCommits, contributors);
          console.log(`[${new Date().toISOString()}] ✅ Found ${anomalies.length} anomalous commits`);
        } catch (error: any) {
          console.warn(`[${new Date().toISOString()}] ⚠️ Anomaly detection failed: ${error.message}`);
        }
      }
    } else {
      console.log(`[${new Date().toISOString()}] ⏭️ Skipping commit analysis (no git repo)`);
    }

    // Calculate maintainer analysis status based on contributor data
    let maintainerAnalysisStatus: 'pass' | 'warning' | 'fail' = 'pass';
    if (contributors.length === 0) {
      maintainerAnalysisStatus = 'warning';
    } else if (contributors.length === 1) {
      // Single contributor is a risk (bus factor)
      maintainerAnalysisStatus = 'warning';
    }

    // Prepare full results
    const results: FullAnalysisResults = {
      name: packageData.name,
      latestVersion,
      publishedAt,
      hasInstallScripts: scriptCapabilities.detectedScripts.length > 0,
      installScripts: scriptCapabilities.detectedScripts.length > 0
        ? {
            preinstall: versionData.scripts?.preinstall,
            postinstall: versionData.scripts?.postinstall,
            install: versionData.scripts?.install,
          }
        : undefined,
      maintainers: maintainers.map((m: any) => ({
        name: m.name || m.username || 'unknown',
        email: m.email,
      })),
      repository: rawRepository || undefined,
      githubUrl: githubUrl || undefined,
      repoCloned: fs.existsSync(gitDirForCommits),
      
      // Security check results
      registryIntegrity,
      scriptCapabilities,
      entropyAnalysis,
      
      // Commit analysis summary
      commitsAnalyzed: commits.length,
      contributorsFound: contributors.length,
      anomaliesDetected: anomalies.length,
      topAnomalyScore: anomalies.length > 0 
        ? Math.max(...anomalies.map(a => a.totalScore))
        : 0,
      
      // Status summaries
      registryIntegrityStatus: registryIntegrity.status,
      installScriptsStatus: scriptCapabilities.status,
      entropyAnalysisStatus: entropyAnalysis.status,
      maintainerAnalysisStatus,
    };

    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}] ✅ Analysis complete for ${packageName}`);
    console.log(`[${new Date().toISOString()}] ========================================`);
    console.log(`[${new Date().toISOString()}]    Registry Integrity: ${registryIntegrity.status}`);
    console.log(`[${new Date().toISOString()}]    Script Capabilities: ${scriptCapabilities.status}`);
    console.log(`[${new Date().toISOString()}]    Entropy Analysis: ${entropyAnalysis.status}`);
    console.log(`[${new Date().toISOString()}]    Maintainer Analysis: ${maintainerAnalysisStatus}`);
    console.log(`[${new Date().toISOString()}]    Commits: ${commits.length}, Contributors: ${contributors.length}, Anomalies: ${anomalies.length}`);

    return {
      success: true,
      data: results,
      tmpDir,
      commits: commits.slice(0, 500), // Store only the most recent 500; profiles built from all
      contributors,
      anomalies,
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Failed to analyze ${packageName}:`, error.message);
    
    return {
      success: false,
      error: error.message,
      tmpDir,
    };
  }
}

/**
 * Analyze a specific package version for auto-bump: registry integrity, install scripts, entropy only.
 * Used by the auto-bump worker to vet a new version before creating PRs.
 */
export async function analyzePackageVersion(
  packageName: string,
  version: string
): Promise<{ success: boolean; data?: FullAnalysisResults; tmpDir?: string; error?: string }> {
  const tmpDir = createTempDir(`${packageName}-${version}`);
  const npmDir = path.join(tmpDir, 'npm');

  try {
    console.log(`[${new Date().toISOString()}] 🚀 Analyzing ${packageName}@${version} for auto-bump`);
    const encodedName = encodeURIComponent(packageName);
    const response = await fetch(`https://registry.npmjs.org/${encodedName}`);
    if (!response.ok) throw new Error(`npm registry returned ${response.status}`);
    const packageData = await response.json() as {
      name: string;
      versions?: Record<string, { scripts?: Record<string, string> }>;
      time?: Record<string, string>;
      repository?: string | { url?: string };
    };
    const versionData = packageData.versions?.[version];
    if (!versionData) throw new Error(`Version ${version} not found in registry`);
    const publishedAt = packageData.time?.[version] || null;
    const rawRepository = typeof packageData.repository === 'string'
      ? packageData.repository
      : (packageData.repository as any)?.url || undefined;

    let registryIntegrity: RegistryIntegrityResult;
    try {
      registryIntegrity = await checkRegistryIntegrity(
        packageName,
        version,
        rawRepository,
        tmpDir
      );
    } catch (error: any) {
      registryIntegrity = {
        status: 'fail',
        modifiedFiles: [],
        tagUsed: null,
        npmFilesCount: 0,
        gitFilesCount: 0,
        error: error.message,
      };
    }

    let scriptCapabilities: ScriptCapabilitiesResult;
    try {
      scriptCapabilities = analyzeScriptCapabilities(npmDir);
    } catch (error: any) {
      scriptCapabilities = {
        status: 'warning',
        detectedScripts: [],
        hasNetworkAccess: false,
        hasShellExecution: false,
        hasDangerousPatterns: false,
        dangerousPatterns: [],
      };
    }

    let entropyAnalysis: EntropyAnalysisResult;
    try {
      entropyAnalysis = await analyzeEntropy(npmDir);
    } catch (error: any) {
      entropyAnalysis = {
        status: 'warning',
        highEntropyFiles: [],
        avgEntropy: 0,
        maxEntropy: 0,
        filesAnalyzed: 0,
        totalSize: 0,
      };
    }

    const results: FullAnalysisResults = {
      name: packageName,
      latestVersion: version,
      publishedAt: publishedAt ? new Date(publishedAt).toISOString() : null,
      hasInstallScripts: !!versionData.scripts && Object.keys(versionData.scripts).length > 0,
      installScripts: versionData.scripts,
      registryIntegrity,
      scriptCapabilities,
      entropyAnalysis,
      commitsAnalyzed: 0,
      contributorsFound: 0,
      anomaliesDetected: 0,
      topAnomalyScore: 0,
      registryIntegrityStatus: registryIntegrity.status,
      installScriptsStatus: scriptCapabilities.status,
      entropyAnalysisStatus: entropyAnalysis.status,
      maintainerAnalysisStatus: 'pass',
    };

    return { success: true, data: results, tmpDir };
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
      tmpDir,
    };
  }
}

// Re-export cleanup functions
export { cleanupRepository } from './github';
