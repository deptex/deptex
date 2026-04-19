import { CommitDetails } from './commit-extractor';

export interface ContributorProfile {
  authorEmail: string;
  authorName: string;
  totalCommits: number;
  avgLinesAdded: number;
  avgLinesDeleted: number;
  avgFilesChanged: number;
  stddevLinesAdded: number;
  stddevLinesDeleted: number;
  stddevFilesChanged: number;
  avgCommitMessageLength: number;
  stddevCommitMessageLength: number;
  insertToDeleteRatio: number;
  commitTimeHistogram: Record<string, number>; // {"0:00": count, "1:00": count, ...}
  typicalDaysActive: Record<string, number>; // {"Monday": count, "Tuesday": count, ...}
  commitTimeHeatmap: number[][]; // 7x24 grid: [day][hour] = commit count
  filesWorkedOn: Record<string, number>; // {"path/to/file": count, ...}
  firstCommitDate: Date;
  lastCommitDate: Date;
}

/**
 * Build contributor profiles from a list of commits
 * This creates statistical baselines for each contributor's behavior
 */
export function buildContributorProfiles(commits: CommitDetails[]): ContributorProfile[] {
  console.log(`[${new Date().toISOString()}] 👥 Building contributor profiles from ${commits.length} commits...`);
  
  // Group commits by author email
  const contributorMap = new Map<string, {
    authorEmail: string;
    authorName: string;
    totalCommits: number;
    linesAdded: number[];
    linesDeleted: number[];
    filesChanged: number[];
    timestamps: Date[];
    messageLengths: number[];
    filesWorkedOn: Map<string, number>;
  }>();

  for (const commit of commits) {
    const email = commit.authorEmail.toLowerCase();
    
    if (!contributorMap.has(email)) {
      contributorMap.set(email, {
        authorEmail: email,
        authorName: commit.author,
        totalCommits: 0,
        linesAdded: [],
        linesDeleted: [],
        filesChanged: [],
        timestamps: [],
        messageLengths: [],
        filesWorkedOn: new Map<string, number>(),
      });
    }

    const profile = contributorMap.get(email)!;
    profile.totalCommits++;
    profile.linesAdded.push(commit.linesAdded);
    profile.linesDeleted.push(commit.linesDeleted);
    profile.filesChanged.push(commit.filesChanged);
    profile.timestamps.push(commit.timestamp);
    profile.messageLengths.push(commit.message.length);

    // Track files worked on from diff data
    if (commit.diffData?.filesChanged) {
      for (const file of commit.diffData.filesChanged) {
        const currentCount = profile.filesWorkedOn.get(file) || 0;
        profile.filesWorkedOn.set(file, currentCount + 1);
      }
    }
  }

  // Convert to final profile format with calculated statistics
  const profiles: ContributorProfile[] = [];
  
  for (const data of contributorMap.values()) {
    // Skip contributors with no valid timestamps
    const validTimestamps = data.timestamps.filter(t => t && !isNaN(t.getTime()));
    if (validTimestamps.length === 0) {
      console.warn(`⚠️ Skipping contributor ${data.authorEmail} - no valid timestamps`);
      continue;
    }

    // Calculate averages
    const avgLinesAdded = calculateAverage(data.linesAdded);
    const avgLinesDeleted = calculateAverage(data.linesDeleted);
    const avgFilesChanged = calculateAverage(data.filesChanged);
    const avgCommitMessageLength = calculateAverage(data.messageLengths);

    // Calculate standard deviations
    const stddevLinesAdded = calculateStandardDeviation(data.linesAdded);
    const stddevLinesDeleted = calculateStandardDeviation(data.linesDeleted);
    const stddevFilesChanged = calculateStandardDeviation(data.filesChanged);
    const stddevCommitMessageLength = calculateStandardDeviation(data.messageLengths);

    // Calculate insert-to-delete ratio
    const totalLinesAdded = data.linesAdded.reduce((a, b) => a + b, 0);
    const totalLinesDeleted = data.linesDeleted.reduce((a, b) => a + b, 0);
    const insertToDeleteRatio = totalLinesDeleted === 0 ? 999 : totalLinesAdded / totalLinesDeleted;

    // Build time-based histograms
    const commitTimeHistogram = buildCommitTimeHistogram(validTimestamps);
    const typicalDaysActive = buildTypicalDaysActive(validTimestamps);
    const commitTimeHeatmap = buildCommitTimeHeatmap(validTimestamps);

    // Convert files worked on to object
    const filesWorkedOn = Object.fromEntries(data.filesWorkedOn);

    // Get first and last commit dates
    const firstCommitDate = new Date(Math.min(...validTimestamps.map(t => t.getTime())));
    const lastCommitDate = new Date(Math.max(...validTimestamps.map(t => t.getTime())));

    profiles.push({
      authorEmail: data.authorEmail,
      authorName: data.authorName,
      totalCommits: data.totalCommits,
      avgLinesAdded,
      avgLinesDeleted,
      avgFilesChanged,
      stddevLinesAdded,
      stddevLinesDeleted,
      stddevFilesChanged,
      avgCommitMessageLength,
      stddevCommitMessageLength,
      insertToDeleteRatio,
      commitTimeHistogram,
      typicalDaysActive,
      commitTimeHeatmap,
      filesWorkedOn,
      firstCommitDate,
      lastCommitDate,
    });
  }

  console.log(`[${new Date().toISOString()}] ✅ Built ${profiles.length} contributor profiles`);
  return profiles;
}

/**
 * Calculate average of an array of numbers
 */
function calculateAverage(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

/**
 * Calculate standard deviation of an array of numbers
 */
function calculateStandardDeviation(values: number[]): number {
  if (values.length === 0) return 0;
  const mean = calculateAverage(values);
  const variance = values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;
  return Math.sqrt(variance);
}

/**
 * Build commit time histogram (hour of day distribution)
 */
function buildCommitTimeHistogram(timestamps: Date[]): Record<string, number> {
  const histogram: Record<string, number> = {};
  
  for (const timestamp of timestamps) {
    const hour = timestamp.getHours();
    const key = `${hour}:00`;
    histogram[key] = (histogram[key] || 0) + 1;
  }
  
  return histogram;
}

/**
 * Build typical days active (day of week distribution)
 */
function buildTypicalDaysActive(timestamps: Date[]): Record<string, number> {
  const daysActive: Record<string, number> = {};
  const dayNames = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  
  for (const timestamp of timestamps) {
    const dayOfWeek = timestamp.getDay();
    const dayName = dayNames[dayOfWeek];
    daysActive[dayName] = (daysActive[dayName] || 0) + 1;
  }
  
  return daysActive;
}

/**
 * Build commit time heatmap (7x24 grid)
 * Format: [day][hour] where day is 0-6 (Sunday-Saturday) and hour is 0-23
 */
function buildCommitTimeHeatmap(timestamps: Date[]): number[][] {
  // Initialize 7x24 grid (7 days, 24 hours)
  const heatmap: number[][] = Array(7).fill(null).map(() => Array(24).fill(0));
  
  for (const timestamp of timestamps) {
    const dayOfWeek = timestamp.getDay(); // 0 = Sunday, 6 = Saturday
    const hour = timestamp.getHours(); // 0-23
    
    if (dayOfWeek >= 0 && dayOfWeek < 7 && hour >= 0 && hour < 24) {
      heatmap[dayOfWeek][hour]++;
    }
  }
  
  return heatmap;
}

/**
 * Get a contributor profile by email from a list of profiles
 */
export function getContributorByEmail(
  profiles: ContributorProfile[],
  email: string
): ContributorProfile | undefined {
  return profiles.find(p => p.authorEmail.toLowerCase() === email.toLowerCase());
}
