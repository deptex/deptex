import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

export interface HighEntropyFile {
  path: string;
  entropy: number;
  size: number;
}

export interface EntropyAnalysisResult {
  status: 'pass' | 'warning' | 'fail';
  highEntropyFiles: HighEntropyFile[];
  avgEntropy: number;
  maxEntropy: number;
  filesAnalyzed: number;
  totalSize: number;
}

// Entropy threshold - files above this are considered "high entropy" (potentially obfuscated)
const HIGH_ENTROPY_THRESHOLD = 5.5;

// File extensions to analyze
const ANALYZABLE_EXTENSIONS = ['.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs'];

// Directories that commonly contain minified/obfuscated code (expected high entropy)
const EXPECTED_HIGH_ENTROPY_DIRS = ['dist', 'build', 'bundle', 'min', 'minified', 'vendor'];

// Maximum file size to analyze (5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024;

/**
 * Calculate Shannon Entropy for a string
 * Higher entropy = more randomness/complexity
 * 
 * Normal source code: ~4.0 - 5.0
 * Minified code: ~5.0 - 5.8
 * Obfuscated/encrypted: ~5.8 - 8.0
 */
export function calculateShannonEntropy(content: string): number {
  if (!content || content.length === 0) return 0;

  const freq: Record<string, number> = {};
  
  for (const char of content) {
    freq[char] = (freq[char] || 0) + 1;
  }

  const len = content.length;
  let entropy = 0;

  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Analyze entropy of all JS/TS files in a directory
 * 
 * @param npmDir - Path to the extracted npm tarball
 * @returns EntropyAnalysisResult
 */
export async function analyzeEntropy(npmDir: string): Promise<EntropyAnalysisResult> {
  console.log(`[${new Date().toISOString()}] 🔍 Analyzing file entropy in ${npmDir}...`);

  const highEntropyFiles: HighEntropyFile[] = [];
  let totalEntropy = 0;
  let maxEntropy = 0;
  let filesAnalyzed = 0;
  let totalSize = 0;

  try {
    // Find all JS/TS files
    const pattern = `**/*.{js,ts,jsx,tsx,mjs,cjs}`;
    const files = await glob(pattern, {
      cwd: npmDir,
      nodir: true,
      ignore: ['**/node_modules/**'],
    });

    console.log(`[${new Date().toISOString()}] 📁 Found ${files.length} JS/TS files to analyze`);

    for (const relPath of files) {
      const fullPath = path.join(npmDir, relPath);
      
      try {
        const stat = fs.statSync(fullPath);
        
        // Skip files that are too large
        if (stat.size > MAX_FILE_SIZE) {
          console.log(`[${new Date().toISOString()}] ⏭️ Skipping large file: ${relPath} (${(stat.size / 1024 / 1024).toFixed(2)}MB)`);
          continue;
        }

        // Skip empty files
        if (stat.size === 0) continue;

        const content = fs.readFileSync(fullPath, 'utf-8');
        const entropy = calculateShannonEntropy(content);

        filesAnalyzed++;
        totalEntropy += entropy;
        totalSize += stat.size;
        
        if (entropy > maxEntropy) {
          maxEntropy = entropy;
        }

        // Check if entropy is above threshold
        if (entropy > HIGH_ENTROPY_THRESHOLD) {
          // Check if file is in an expected high-entropy directory
          const isExpectedHighEntropy = EXPECTED_HIGH_ENTROPY_DIRS.some(dir => 
            relPath.toLowerCase().includes(`/${dir}/`) || 
            relPath.toLowerCase().startsWith(`${dir}/`)
          );

          // Always record high entropy files, but we'll use location to determine status
          highEntropyFiles.push({
            path: relPath,
            entropy: Math.round(entropy * 100) / 100,
            size: stat.size,
          });

          if (!isExpectedHighEntropy) {
            console.log(`[${new Date().toISOString()}] ⚠️ High entropy file in unexpected location: ${relPath} (entropy: ${entropy.toFixed(2)})`);
          }
        }
      } catch (fileError: any) {
        // Skip files we can't read (e.g., binary files mistakenly included)
        console.warn(`[${new Date().toISOString()}] ⚠️ Could not analyze ${relPath}: ${fileError.message}`);
      }
    }

    // Calculate average entropy
    const avgEntropy = filesAnalyzed > 0 ? totalEntropy / filesAnalyzed : 0;

    // Determine status
    let status: 'pass' | 'warning' | 'fail' = 'pass';

    if (highEntropyFiles.length > 0) {
      // Check if any high entropy files are in unexpected locations
      const unexpectedHighEntropyFiles = highEntropyFiles.filter(f => {
        return !EXPECTED_HIGH_ENTROPY_DIRS.some(dir => 
          f.path.toLowerCase().includes(`/${dir}/`) || 
          f.path.toLowerCase().startsWith(`${dir}/`)
        );
      });

      if (unexpectedHighEntropyFiles.length > 0) {
        // High entropy files in src/, lib/, or root - suspicious
        const veryHighEntropyCount = unexpectedHighEntropyFiles.filter(f => f.entropy > 6.0).length;
        status = veryHighEntropyCount > 0 ? 'fail' : 'warning';
      } else {
        // All high entropy files are in expected locations (dist/, build/, etc.)
        status = 'warning';
      }
    }

    console.log(`[${new Date().toISOString()}] 📊 Entropy analysis: ${status}`);
    console.log(`[${new Date().toISOString()}]    Files analyzed: ${filesAnalyzed}`);
    console.log(`[${new Date().toISOString()}]    Average entropy: ${avgEntropy.toFixed(2)}`);
    console.log(`[${new Date().toISOString()}]    Max entropy: ${maxEntropy.toFixed(2)}`);
    console.log(`[${new Date().toISOString()}]    High entropy files: ${highEntropyFiles.length}`);

    return {
      status,
      highEntropyFiles,
      avgEntropy: Math.round(avgEntropy * 100) / 100,
      maxEntropy: Math.round(maxEntropy * 100) / 100,
      filesAnalyzed,
      totalSize,
    };
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Entropy analysis failed:`, error.message);
    return {
      status: 'warning',
      highEntropyFiles: [],
      avgEntropy: 0,
      maxEntropy: 0,
      filesAnalyzed: 0,
      totalSize: 0,
    };
  }
}

/**
 * Get a human-readable description of entropy level
 */
export function getEntropyDescription(entropy: number): string {
  if (entropy < 4.0) return 'Low (simple/repetitive code)';
  if (entropy < 5.0) return 'Normal (typical source code)';
  if (entropy < 5.5) return 'Moderate (complex or minified)';
  if (entropy < 6.0) return 'High (likely minified/bundled)';
  if (entropy < 6.5) return 'Very High (heavily obfuscated)';
  return 'Extreme (encrypted or binary data)';
}
