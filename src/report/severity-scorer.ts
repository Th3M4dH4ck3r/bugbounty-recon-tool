/**
 * CVSS-like severity scoring for smart contract vulnerabilities
 */

import { Finding, Severity, SeverityScore } from '../types';

/**
 * Calculate CVSS-like score for a finding
 */
export function calculateCvssScore(finding: Finding): number {
  const impactScore = getImpactScore(finding.severity, finding.impact);
  const likelihoodScore = getLikelihoodScore(finding.likelihood);
  const confidenceScore = getConfidenceScore(finding.confidence);

  // Weighted calculation: Impact (50%), Likelihood (30%), Confidence (20%)
  const score = (impactScore * 0.5) + (likelihoodScore * 0.3) + (confidenceScore * 0.2);

  return Math.min(10, Math.max(0, score));
}

/**
 * Get impact score (0-10)
 */
function getImpactScore(severity: Severity, impact: string): number {
  // Base score from severity
  const severityScores: Record<Severity, number> = {
    critical: 10,
    high: 7.5,
    medium: 5,
    low: 2.5,
    informational: 0,
  };

  let score = severityScores[severity] || 5;

  // Adjust based on impact description keywords
  const impactLower = impact.toLowerCase();

  if (impactLower.includes('complete loss') || impactLower.includes('drain')) {
    score = Math.min(10, score + 1);
  } else if (impactLower.includes('significant loss')) {
    score = Math.min(10, score + 0.5);
  } else if (impactLower.includes('limited')) {
    score = Math.max(0, score - 0.5);
  }

  return score;
}

/**
 * Get likelihood score (0-10)
 */
function getLikelihoodScore(likelihood: string): number {
  const scores: Record<string, number> = {
    high: 10,
    medium: 5,
    low: 2,
  };

  return scores[likelihood.toLowerCase()] || 5;
}

/**
 * Get confidence score (0-10)
 */
function getConfidenceScore(confidence: string): number {
  const scores: Record<string, number> = {
    high: 10,
    medium: 6,
    low: 3,
  };

  return scores[confidence.toLowerCase()] || 6;
}

/**
 * Calculate full severity score object
 */
export function calculateSeverityScore(finding: Finding): SeverityScore {
  const cvssScore = calculateCvssScore(finding);

  return {
    severity: finding.severity,
    impact: finding.impact as 'high' | 'medium' | 'low',
    likelihood: finding.likelihood as 'high' | 'medium' | 'low',
    confidence: finding.confidence,
    cvss_score: cvssScore,
    cvss_vector: generateCvssVector(finding),
  };
}

/**
 * Generate CVSS-like vector string
 */
function generateCvssVector(finding: Finding): string {
  const impact = finding.impact.toLowerCase().includes('high') ? 'H' :
                 finding.impact.toLowerCase().includes('medium') ? 'M' : 'L';

  const likelihood = finding.likelihood.charAt(0).toUpperCase();
  const confidence = finding.confidence.charAt(0).toUpperCase();

  return `SC:1.0/I:${impact}/L:${likelihood}/C:${confidence}`;
}

/**
 * Get bounty severity label for bug bounty platforms
 */
export function getBountySeverity(finding: Finding): string {
  const score = calculateCvssScore(finding);

  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score >= 0.1) return 'Low';
  return 'Informational';
}

/**
 * Get recommended bounty amount based on severity
 * (This is a guideline - actual amounts vary by program)
 */
export function getRecommendedBounty(finding: Finding): { min: number; max: number } {
  const severity = getBountySeverity(finding);

  const ranges: Record<string, { min: number; max: number }> = {
    Critical: { min: 50000, max: 500000 },
    High: { min: 10000, max: 50000 },
    Medium: { min: 2000, max: 10000 },
    Low: { min: 500, max: 2000 },
    Informational: { min: 0, max: 500 },
  };

  return ranges[severity] || { min: 0, max: 0 };
}
