import { CommitDetails } from './commit-extractor';
import { ContributorProfile } from './contributor-profile';

export interface AnomalyScoreBreakdown {
  factor: string;
  points: number;
  reason: string;
}

export interface AnomalyResult {
  commitSha: string;
  contributorEmail: string;
  totalScore: number;
  breakdown: AnomalyScoreBreakdown[];
}

/**
 * Calculate anomaly score for a commit against contributor baseline
 * Higher score = more suspicious/anomalous
 * 
 * Scoring factors:
 * - Files changed: 10-15 points if 2-3+ std dev above mean
 * - Lines changed: 10-15 points if 2-3+ std dev above mean
 * - Message length: 5 points if unusual
 * - Insert/delete ratio: 5 points if >50% different
 * - Unusual commit time: 5 points if <5% of commits at that hour
 * - Unusual day: 5 points if <10% of commits on that day
 * - New files worked on: 10 points per new file, max 30
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
  contributorProfiles: ContributorProfile[]
): AnomalyResult[] {
  console.log(`[${new Date().toISOString()}] 🔍 Calculating anomaly scores for ${commits.length} commits...`);
  
  const results: AnomalyResult[] = [];
  const profileMap = new Map(contributorProfiles.map(p => [p.authorEmail.toLowerCase(), p]));

  for (const commit of commits) {
    const profile = profileMap.get(commit.authorEmail.toLowerCase());
    
    if (!profile) {
      // Skip commits from contributors without profiles (shouldn't happen)
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
      reason: `Unusually high number of files changed (${commit.filesChanged} files vs avg ${avg.toFixed(1)}, ${deviation.toFixed(1)} std dev above mean)`,
    };
  } else if (deviation >= 2) {
    return {
      factor: 'files_changed',
      points: 10,
      reason: `Unusually high number of files changed (${commit.filesChanged} files vs avg ${avg.toFixed(1)}, ${deviation.toFixed(1)} std dev above mean)`,
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
      reason: `Unusually high number of lines changed (${totalLines} lines vs avg ${avgTotal.toFixed(1)}, ${deviation.toFixed(1)} std dev above mean)`,
    };
  } else if (deviation >= 2) {
    return {
      factor: 'lines_changed',
      points: 10,
      reason: `Unusually high number of lines changed (${totalLines} lines vs avg ${avgTotal.toFixed(1)}, ${deviation.toFixed(1)} std dev above mean)`,
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

  if (deviation >= 2) {
    if (messageLength > avg) {
      return {
        factor: 'message_length',
        points: 5,
        reason: `Unusually long commit message (${messageLength} chars vs avg ${avg.toFixed(1)}, ${deviation.toFixed(1)} std dev above mean)`,
      };
    } else {
      return {
        factor: 'message_length',
        points: 5,
        reason: `Unusually short commit message (${messageLength} chars vs avg ${avg.toFixed(1)}, ${deviation.toFixed(1)} std dev below mean)`,
      };
    }
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

  if (percentDiff > 50) {
    return {
      factor: 'insert_delete_ratio',
      points: 5,
      reason: `Unusual insert-to-delete ratio (${commitRatio.toFixed(2)} vs typical ${profileRatio.toFixed(2)}, ${percentDiff.toFixed(1)}% difference)`,
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

  if (percentage < 5) {
    return {
      factor: 'abnormal_time',
      points: 5,
      reason: `Unusual time for contributor to commit (${hour}:00, only ${percentage.toFixed(1)}% of commits at this hour)`,
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

  if (percentage < 10) {
    return {
      factor: 'abnormal_day',
      points: 5,
      reason: `Unusual day for contributor to commit (${dayName}, only ${percentage.toFixed(1)}% of commits on this day)`,
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

  // Cap at 3 files (max 30 points)
  const filesToCount = newFiles.slice(0, 3);
  const points = filesToCount.length * 10;
  const fileList = filesToCount.map(f => f.split('/').pop()).join(', ');

  return {
    factor: 'new_files',
    points,
    reason: `Working on ${filesToCount.length} new file(s) not in contributor's history: ${fileList}`,
  };
}
