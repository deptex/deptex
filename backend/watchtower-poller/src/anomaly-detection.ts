import { CommitDetails } from './incremental-analyzer';
import { ContributorProfile, AnomalyScoreBreakdown, AnomalyResult } from './storage';

/**
 * Calculate anomaly score for a commit against contributor baseline
 * Higher score = more suspicious/anomalous
 * 
 * Scoring factors (graduated scoring for more variation):
 * - Files changed: 6/10/15 points based on deviation severity (1.5/2/3+ std dev)
 * - Lines changed: 6/10/15 points based on deviation severity (1.5/2/3+ std dev)
 * - Message length: 3/5/8 points based on deviation severity
 * - Insert/delete ratio: 3/5/8 points based on difference severity
 * - Unusual commit time: 3/5/7 points based on rarity
 * - Unusual day: 2/4/6 points based on rarity
 * - New files worked on: 4/8/12 points per file (max 36)
 * - Security-sensitive files: 5/10/15 points based on file criticality
 * - First-time contributor: 8 points for new contributors
 * - Sensitive keywords: 3/6/12 points based on keyword severity
 */
export function calculateAnomalyScore(
  commit: CommitDetails,
  contributorProfile: ContributorProfile
): AnomalyResult {
  const breakdown: AnomalyScoreBreakdown[] = [];

  // Check each anomaly type
  const filesChangedResult = checkFilesChangedAnomaly(commit, contributorProfile);
  if (filesChangedResult.points > 0) breakdown.push(filesChangedResult);

  const linesChangedResult = checkLinesChangedAnomaly(commit, contributorProfile);
  if (linesChangedResult.points > 0) breakdown.push(linesChangedResult);

  const messageLengthResult = checkMessageLengthAnomaly(commit, contributorProfile);
  if (messageLengthResult.points > 0) breakdown.push(messageLengthResult);

  const insertDeleteRatioResult = checkInsertDeleteRatioAnomaly(commit, contributorProfile);
  if (insertDeleteRatioResult.points > 0) breakdown.push(insertDeleteRatioResult);

  const timeAnomalyResult = checkTimeAnomaly(commit, contributorProfile);
  if (timeAnomalyResult.points > 0) breakdown.push(timeAnomalyResult);

  const dayAnomalyResult = checkDayAnomaly(commit, contributorProfile);
  if (dayAnomalyResult.points > 0) breakdown.push(dayAnomalyResult);

  const newFilesResult = checkNewFilesAnomaly(commit, contributorProfile);
  if (newFilesResult.points > 0) breakdown.push(newFilesResult);

  // NEW: Security-sensitive file detection
  const securityFilesResult = checkSecuritySensitiveFiles(commit);
  if (securityFilesResult.points > 0) breakdown.push(securityFilesResult);

  // NEW: First-time contributor detection
  const firstTimeResult = checkFirstTimeContributor(contributorProfile);
  if (firstTimeResult.points > 0) breakdown.push(firstTimeResult);

  // NEW: Sensitive keyword detection in commit message
  const keywordResult = checkSensitiveKeywords(commit);
  if (keywordResult.points > 0) breakdown.push(keywordResult);

  const totalScore = breakdown.reduce((sum, item) => sum + item.points, 0);

  return {
    commitSha: commit.sha,
    contributorEmail: commit.authorEmail,
    totalScore,
    breakdown,
  };
}

/**
 * Calculate anomaly scores for multiple commits
 */
export function calculateAnomaliesForCommits(
  commits: CommitDetails[],
  contributorProfiles: Map<string, ContributorProfile>
): AnomalyResult[] {
  console.log(`[${new Date().toISOString()}] 🔍 Calculating anomaly scores for ${commits.length} commits...`);

  const results: AnomalyResult[] = [];

  for (const commit of commits) {
    const profile = contributorProfiles.get(commit.authorEmail.toLowerCase());

    if (!profile) {
      // Skip commits from contributors without profiles
      console.warn(`⚠️ No profile found for contributor ${commit.authorEmail}`);
      continue;
    }

    const result = calculateAnomalyScore(commit, profile);

    // Only include commits with anomaly scores > 0
    if (result.totalScore > 0) {
      results.push(result);
    }
  }

  console.log(`[${new Date().toISOString()}] ✅ Found ${results.length} anomalous commits out of ${commits.length} total`);
  return results;
}

/**
 * Check files changed anomaly
 */
function checkFilesChangedAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  const avg = profile.avgFilesChanged;
  const stddev = profile.stddevFilesChanged;

  if (stddev === 0) {
    return { factor: 'files_changed', points: 0, reason: '' };
  }

  const deviation = (commit.filesChanged - avg) / stddev;

  if (deviation >= 3) {
    return {
      factor: 'files_changed',
      points: 15,
      reason: `Extremely high file count: ${commit.filesChanged} files touched (typical: ${avg.toFixed(1)} ±${stddev.toFixed(1)}). This is ${deviation.toFixed(1)}σ above normal—possible bulk change or automated commit.`,
    };
  } else if (deviation >= 2) {
    return {
      factor: 'files_changed',
      points: 10,
      reason: `High file count: ${commit.filesChanged} files (typical: ${avg.toFixed(1)}). At ${deviation.toFixed(1)}σ above mean, this warrants review.`,
    };
  } else if (deviation >= 1.5) {
    return {
      factor: 'files_changed',
      points: 6,
      reason: `Above-average file count: ${commit.filesChanged} files vs typical ${avg.toFixed(1)} (${deviation.toFixed(1)}σ deviation).`,
    };
  }

  return { factor: 'files_changed', points: 0, reason: '' };
}

/**
 * Check lines changed anomaly
 */
function checkLinesChangedAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  const totalLines = commit.linesAdded + commit.linesDeleted;
  const avgTotal = profile.avgLinesAdded + profile.avgLinesDeleted;
  const stddevTotal = Math.sqrt(
    Math.pow(profile.stddevLinesAdded, 2) + Math.pow(profile.stddevLinesDeleted, 2)
  );

  if (stddevTotal === 0) {
    return { factor: 'lines_changed', points: 0, reason: '' };
  }

  const deviation = (totalLines - avgTotal) / stddevTotal;

  if (deviation >= 3) {
    return {
      factor: 'lines_changed',
      points: 15,
      reason: `Extremely high code volume: ${totalLines.toLocaleString()} lines changed (+${commit.linesAdded.toLocaleString()}/-${commit.linesDeleted.toLocaleString()}). Typical: ${avgTotal.toFixed(0)} lines. This is ${deviation.toFixed(1)}σ above normal.`,
    };
  } else if (deviation >= 2) {
    return {
      factor: 'lines_changed',
      points: 10,
      reason: `High code volume: ${totalLines.toLocaleString()} lines vs typical ${avgTotal.toFixed(0)}. At ${deviation.toFixed(1)}σ, this is a notably large commit.`,
    };
  } else if (deviation >= 1.5) {
    return {
      factor: 'lines_changed',
      points: 6,
      reason: `Above-average code changes: ${totalLines.toLocaleString()} lines vs typical ${avgTotal.toFixed(0)} (${deviation.toFixed(1)}σ deviation).`,
    };
  }

  return { factor: 'lines_changed', points: 0, reason: '' };
}

/**
 * Check commit message length anomaly
 */
function checkMessageLengthAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  const messageLength = commit.message.length;
  const avg = profile.avgCommitMessageLength;
  const stddev = profile.stddevCommitMessageLength;

  if (stddev === 0) {
    return { factor: 'message_length', points: 0, reason: '' };
  }

  const deviation = Math.abs(messageLength - avg) / stddev;

  if (deviation >= 3) {
    if (messageLength > avg) {
      return {
        factor: 'message_length',
        points: 8,
        reason: `Extremely long commit message: ${messageLength} chars (typical: ${avg.toFixed(0)} chars). At ${deviation.toFixed(1)}σ above normal, this may indicate verbose justification or embedded data.`,
      };
    } else {
      return {
        factor: 'message_length',
        points: 8,
        reason: `Extremely short commit message: ${messageLength} chars (typical: ${avg.toFixed(0)} chars). At ${deviation.toFixed(1)}σ below normal, this may indicate rushed or obfuscated commit.`,
      };
    }
  } else if (deviation >= 2) {
    if (messageLength > avg) {
      return {
        factor: 'message_length',
        points: 5,
        reason: `Long commit message: ${messageLength} chars vs typical ${avg.toFixed(0)} (${deviation.toFixed(1)}σ deviation).`,
      };
    } else {
      return {
        factor: 'message_length',
        points: 5,
        reason: `Short commit message: ${messageLength} chars vs typical ${avg.toFixed(0)} (${deviation.toFixed(1)}σ deviation).`,
      };
    }
  } else if (deviation >= 1.5) {
    return {
      factor: 'message_length',
      points: 3,
      reason: `Atypical message length: ${messageLength} chars vs typical ${avg.toFixed(0)} (${deviation.toFixed(1)}σ deviation).`,
    };
  }

  return { factor: 'message_length', points: 0, reason: '' };
}

/**
 * Check insert-to-delete ratio anomaly
 */
function checkInsertDeleteRatioAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  if (commit.linesDeleted === 0) {
    return { factor: 'insert_delete_ratio', points: 0, reason: '' };
  }

  const commitRatio = commit.linesAdded / commit.linesDeleted;
  const profileRatio = profile.insertToDeleteRatio;

  if (profileRatio === 0 || profileRatio === 999) {
    return { factor: 'insert_delete_ratio', points: 0, reason: '' };
  }

  // Calculate percentage difference
  const percentDiff = Math.abs((commitRatio - profileRatio) / profileRatio) * 100;

  if (percentDiff > 100) {
    return {
      factor: 'insert_delete_ratio',
      points: 8,
      reason: `Drastically different code pattern: ratio ${commitRatio.toFixed(2)} vs typical ${profileRatio.toFixed(2)} (${percentDiff.toFixed(0)}% difference). This is a major deviation from normal editing behavior.`,
    };
  } else if (percentDiff > 75) {
    return {
      factor: 'insert_delete_ratio',
      points: 5,
      reason: `Unusual code pattern: ratio ${commitRatio.toFixed(2)} vs typical ${profileRatio.toFixed(2)} (${percentDiff.toFixed(0)}% difference).`,
    };
  } else if (percentDiff > 50) {
    return {
      factor: 'insert_delete_ratio',
      points: 3,
      reason: `Slightly unusual insert/delete ratio: ${commitRatio.toFixed(2)} vs typical ${profileRatio.toFixed(2)} (${percentDiff.toFixed(0)}% difference).`,
    };
  }

  return { factor: 'insert_delete_ratio', points: 0, reason: '' };
}

/**
 * Check abnormal time anomaly
 */
function checkTimeAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  const hour = commit.timestamp.getHours();
  const hourKey = `${hour}:00`;
  const histogram = profile.commitTimeHistogram;

  if (!histogram || typeof histogram !== 'object') {
    return { factor: 'abnormal_time', points: 0, reason: '' };
  }

  // Calculate total commits across all hours
  const totalCommits: number = Object.values(histogram).reduce(
    (sum: number, count: unknown) => sum + (typeof count === 'number' ? count : 0),
    0
  );

  if (totalCommits === 0) {
    return { factor: 'abnormal_time', points: 0, reason: '' };
  }

  // Get commits at this hour
  const commitsAtThisHour = typeof histogram[hourKey] === 'number' ? histogram[hourKey] : 0;
  const percentage = (commitsAtThisHour / totalCommits) * 100;

  if (percentage < 2) {
    return {
      factor: 'abnormal_time',
      points: 7,
      reason: `Very unusual commit time: ${hour}:00 (only ${percentage.toFixed(1)}% of this contributor's commits). This time is almost never used by this developer.`,
    };
  } else if (percentage < 5) {
    return {
      factor: 'abnormal_time',
      points: 5,
      reason: `Unusual commit time: ${hour}:00 (only ${percentage.toFixed(1)}% of commits at this hour). Outside normal working pattern.`,
    };
  } else if (percentage < 8) {
    return {
      factor: 'abnormal_time',
      points: 3,
      reason: `Atypical commit time: ${hour}:00 (${percentage.toFixed(1)}% of commits). Slightly outside usual hours.`,
    };
  }

  return { factor: 'abnormal_time', points: 0, reason: '' };
}

/**
 * Check abnormal day anomaly
 */
function checkDayAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  const dayOfWeek = commit.timestamp.getDay();
  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const dayName = dayNames[dayOfWeek];
  const typicalDays = profile.typicalDaysActive;

  if (!typicalDays || typeof typicalDays !== 'object') {
    return { factor: 'abnormal_day', points: 0, reason: '' };
  }

  // Calculate total commits across all days
  const totalCommits: number = Object.values(typicalDays).reduce(
    (sum: number, count: unknown) => sum + (typeof count === 'number' ? count : 0),
    0
  );

  if (totalCommits === 0) {
    return { factor: 'abnormal_day', points: 0, reason: '' };
  }

  // Get commits on this day
  const commitsOnThisDay = typeof typicalDays[dayName] === 'number' ? typicalDays[dayName] : 0;
  const percentage = (commitsOnThisDay / totalCommits) * 100;

  if (percentage < 5) {
    return {
      factor: 'abnormal_day',
      points: 6,
      reason: `Very unusual commit day: ${dayName} (only ${percentage.toFixed(1)}% of commits). This contributor rarely works on ${dayName}s.`,
    };
  } else if (percentage < 10) {
    return {
      factor: 'abnormal_day',
      points: 4,
      reason: `Unusual commit day: ${dayName} (${percentage.toFixed(1)}% of commits). Outside normal working pattern.`,
    };
  } else if (percentage < 15) {
    return {
      factor: 'abnormal_day',
      points: 2,
      reason: `Slightly atypical day: ${dayName} (${percentage.toFixed(1)}% of commits vs more common days).`,
    };
  }

  return { factor: 'abnormal_day', points: 0, reason: '' };
}

/**
 * Check new files anomaly
 */
function checkNewFilesAnomaly(
  commit: CommitDetails,
  profile: ContributorProfile
): AnomalyScoreBreakdown {
  if (!commit.diffData?.filesChanged || !Array.isArray(commit.diffData.filesChanged)) {
    return { factor: 'new_files', points: 0, reason: '' };
  }

  const filesWorkedOn = profile.filesWorkedOn;
  if (!filesWorkedOn || typeof filesWorkedOn !== 'object') {
    return { factor: 'new_files', points: 0, reason: '' };
  }

  const newFiles: string[] = [];
  for (const file of commit.diffData.filesChanged) {
    if (!filesWorkedOn[file] || filesWorkedOn[file] === 0) {
      newFiles.push(file);
    }
  }

  if (newFiles.length === 0) {
    return { factor: 'new_files', points: 0, reason: '' };
  }

  // Graduated scoring based on number of new files
  // 1 file = 4 pts, 2 files = 8 pts each, 3+ files = 12 pts each (max 36)
  const filesToCount = newFiles.slice(0, 3);
  const fileList = filesToCount.map(f => f.split('/').pop()).join(', ');

  let points: number;
  let severityDesc: string;

  if (filesToCount.length >= 3) {
    points = 36;
    severityDesc = 'Significant territory expansion';
  } else if (filesToCount.length === 2) {
    points = 16;
    severityDesc = 'Working in multiple new areas';
  } else {
    points = 4;
    severityDesc = 'Branching into new code';
  }

  return {
    factor: 'new_files',
    points,
    reason: `${severityDesc}: ${filesToCount.length} file(s) not in contributor's history (${fileList}). This contributor has never touched these files before.`,
  };
}

/**
 * Check for changes to security-sensitive files
 * These files have elevated risk for supply chain attacks
 */
function checkSecuritySensitiveFiles(
  commit: CommitDetails
): AnomalyScoreBreakdown {
  if (!commit.diffData?.filesChanged || !Array.isArray(commit.diffData.filesChanged)) {
    return { factor: 'security_sensitive_files', points: 0, reason: '' };
  }

  // Critical files - highest risk for supply chain attacks
  const criticalPatterns = [
    /package\.json$/i,
    /package-lock\.json$/i,
    /\.npmrc$/i,
    /\.yarnrc/i,
    /yarn\.lock$/i,
  ];

  // High-risk files - authentication, configuration, build
  const highRiskPatterns = [
    /\.env/i,
    /config\.(js|ts|json)$/i,
    /auth/i,
    /secret/i,
    /credential/i,
    /\.github\/workflows/i,
    /Dockerfile/i,
    /docker-compose/i,
    /webpack\.config/i,
    /rollup\.config/i,
    /vite\.config/i,
    /tsconfig\.json$/i,
  ];

  // Moderate risk - scripts and entry points
  const moderatePatterns = [
    /scripts\//i,
    /bin\//i,
    /postinstall/i,
    /preinstall/i,
    /install\.js$/i,
    /index\.(js|ts)$/i,
  ];

  const criticalFiles: string[] = [];
  const highRiskFiles: string[] = [];
  const moderateFiles: string[] = [];

  for (const file of commit.diffData.filesChanged) {
    if (criticalPatterns.some(p => p.test(file))) {
      criticalFiles.push(file.split('/').pop() || file);
    } else if (highRiskPatterns.some(p => p.test(file))) {
      highRiskFiles.push(file.split('/').pop() || file);
    } else if (moderatePatterns.some(p => p.test(file))) {
      moderateFiles.push(file.split('/').pop() || file);
    }
  }

  if (criticalFiles.length > 0) {
    return {
      factor: 'security_sensitive_files',
      points: 15,
      reason: `Critical supply chain files modified: ${criticalFiles.join(', ')}. These files control dependencies, build config, or registry auth.`,
    };
  } else if (highRiskFiles.length > 0) {
    return {
      factor: 'security_sensitive_files',
      points: 10,
      reason: `High-risk configuration files modified: ${highRiskFiles.slice(0, 3).join(', ')}${highRiskFiles.length > 3 ? ` (+${highRiskFiles.length - 3} more)` : ''}. Review for unintended changes.`,
    };
  } else if (moderateFiles.length > 0) {
    return {
      factor: 'security_sensitive_files',
      points: 5,
      reason: `Executable/script files modified: ${moderateFiles.slice(0, 3).join(', ')}. These can run during install or startup.`,
    };
  }

  return { factor: 'security_sensitive_files', points: 0, reason: '' };
}

/**
 * Check if this is a first-time contributor to the package
 * New contributors warrant additional scrutiny
 */
function checkFirstTimeContributor(
  contributorProfile: ContributorProfile
): AnomalyScoreBreakdown {
  // If contributor has very few commits, they're new
  if (contributorProfile.totalCommits <= 1) {
    return {
      factor: 'first_time_contributor',
      points: 8,
      reason: `First-time contributor to this package. New contributors warrant additional review for supply chain security.`,
    };
  } else if (contributorProfile.totalCommits <= 3) {
    return {
      factor: 'first_time_contributor',
      points: 4,
      reason: `New contributor (only ${contributorProfile.totalCommits} commits). Limited history for baseline comparison.`,
    };
  }

  return { factor: 'first_time_contributor', points: 0, reason: '' };
}

/**
 * Check for sensitive keywords in commit message
 * Certain keywords may indicate suspicious intent or obfuscation
 */
function checkSensitiveKeywords(
  commit: CommitDetails
): AnomalyScoreBreakdown {
  const message = commit.message.toLowerCase();

  // High severity keywords - often indicate credential handling or obfuscation
  const highSeverityPatterns = [
    { pattern: /password/i, desc: 'password' },
    { pattern: /secret/i, desc: 'secret' },
    { pattern: /credential/i, desc: 'credential' },
    { pattern: /api[_-]?key/i, desc: 'API key' },
    { pattern: /private[_-]?key/i, desc: 'private key' },
    { pattern: /encrypt/i, desc: 'encryption' },
    { pattern: /decrypt/i, desc: 'decryption' },
    { pattern: /obfuscat/i, desc: 'obfuscation' },
    { pattern: /base64/i, desc: 'base64 encoding' },
  ];

  // Medium severity - network/exfiltration related
  const mediumSeverityPatterns = [
    { pattern: /token/i, desc: 'token' },
    { pattern: /auth/i, desc: 'authentication' },
    { pattern: /curl|wget|fetch/i, desc: 'network request' },
    { pattern: /eval\s*\(/i, desc: 'eval()' },
    { pattern: /exec\s*\(/i, desc: 'exec()' },
    { pattern: /child_process/i, desc: 'child process' },
  ];

  // Low severity - might be legitimate but worth noting
  const lowSeverityPatterns = [
    { pattern: /env\b/i, desc: 'environment variable' },
    { pattern: /config/i, desc: 'configuration' },
    { pattern: /hook/i, desc: 'hook' },
  ];

  const highMatches: string[] = [];
  const mediumMatches: string[] = [];
  const lowMatches: string[] = [];

  for (const { pattern, desc } of highSeverityPatterns) {
    if (pattern.test(message)) highMatches.push(desc);
  }
  for (const { pattern, desc } of mediumSeverityPatterns) {
    if (pattern.test(message)) mediumMatches.push(desc);
  }
  for (const { pattern, desc } of lowSeverityPatterns) {
    if (pattern.test(message)) lowMatches.push(desc);
  }

  if (highMatches.length > 0) {
    return {
      factor: 'sensitive_keywords',
      points: 12,
      reason: `Sensitive terms in commit message: ${highMatches.join(', ')}. Review actual changes carefully for credential handling or obfuscation.`,
    };
  } else if (mediumMatches.length >= 2) {
    return {
      factor: 'sensitive_keywords',
      points: 6,
      reason: `Multiple security-relevant terms: ${mediumMatches.join(', ')}. May indicate auth/network changes.`,
    };
  } else if (mediumMatches.length === 1) {
    return {
      factor: 'sensitive_keywords',
      points: 3,
      reason: `Security-relevant term in message: "${mediumMatches[0]}". Worth reviewing if unexpected.`,
    };
  }

  return { factor: 'sensitive_keywords', points: 0, reason: '' };
}
