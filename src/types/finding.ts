/**
 * Core types for security findings and vulnerability analysis
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';
export type Confidence = 'high' | 'medium' | 'low';
export type AnalysisSource = 'static' | 'dynamic' | 'symbolic' | 'fuzz' | 'manual';
export type PocType = 'hardhat-script' | 'foundry-test' | 'brownie-script' | 'typescript' | 'python';

/**
 * Represents a code location in a source file
 */
export interface CodeLocation {
  path: string;
  line_start: number;
  line_end: number;
  column_start?: number;
  column_end?: number;
  snippet?: string;
}

/**
 * Evidence artifact associated with a finding
 */
export interface Evidence {
  type: 'trace' | 'log' | 'screenshot' | 'transaction' | 'storage-diff' | 'call-graph';
  path?: string;
  content?: string;
  description?: string;
}

/**
 * Proof of Concept information
 */
export interface ProofOfConcept {
  path: string;
  type: PocType;
  simulated: boolean;
  description?: string;
  steps?: string[];
  output?: string;
}

/**
 * CVSS-like scoring information
 */
export interface SeverityScore {
  severity: Severity;
  impact: 'high' | 'medium' | 'low';
  likelihood: 'high' | 'medium' | 'low';
  confidence: Confidence;
  cvss_score?: number;
  cvss_vector?: string;
}

/**
 * Main finding structure - matches the required JSON schema
 */
export interface Finding {
  id: string;
  contract: string;
  address?: string;
  source: AnalysisSource;
  rule_id: string;
  title: string;
  severity: Severity;
  impact: string;
  likelihood: string;
  confidence: Confidence;
  recommendation: string;
  description?: string;
  files: CodeLocation[];
  poc?: ProofOfConcept;
  evidence: Evidence[];
  tags?: string[];
  references?: string[];
  created_at?: string;
  updated_at?: string;
}

/**
 * Analysis run metadata
 */
export interface AnalysisRun {
  id: string;
  target: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  findings_count: number;
  findings: Finding[];
  config: Record<string, any>;
  errors?: string[];
}

/**
 * Rule definition for custom static analysis
 */
export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  pattern?: string;
  check: (context: any) => boolean;
  recommendation: string;
  references?: string[];
  enabled?: boolean;
}

/**
 * Contract metadata
 */
export interface ContractInfo {
  name: string;
  path: string;
  address?: string;
  network?: string;
  compiler_version?: string;
  source_code?: string;
  abi?: any[];
  bytecode?: string;
}

/**
 * Scan configuration
 */
export interface ScanConfig {
  target: string;
  analyzers: string[];
  rules?: string[];
  output_dir?: string;
  concurrency?: number;
  timeout?: number;
  fork_url?: string;
  network?: string;
  api_keys?: Record<string, string>;
}
