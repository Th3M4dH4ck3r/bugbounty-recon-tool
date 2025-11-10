/**
 * Configuration types for Scout
 */

export interface ApiKeys {
  etherscan?: string;
  bscscan?: string;
  polygonscan?: string;
  mythx?: string;
  github?: string;
  tenderly?: string;
}

export interface RpcConfig {
  ethereum?: string;
  polygon?: string;
  bsc?: string;
  arbitrum?: string;
  optimism?: string;
  localhost?: string;
}

export interface IntegrationConfig {
  slack?: {
    webhook_url: string;
    channel?: string;
  };
  discord?: {
    webhook_url: string;
  };
  webhook?: {
    url: string;
    headers?: Record<string, string>;
  };
}

export interface ServerConfig {
  enabled: boolean;
  port: number;
  host: string;
  rate_limit: number;
}

export interface SecurityConfig {
  allow_live_tx: boolean;
  max_concurrent_scans: number;
  require_confirmation: boolean;
}

export interface OutputConfig {
  reports_dir: string;
  pocs_dir: string;
  artifacts_dir: string;
  format: 'json' | 'markdown' | 'html' | 'pdf';
}

export interface ScoutConfig {
  api_keys: ApiKeys;
  rpc: RpcConfig;
  integrations?: IntegrationConfig;
  server?: ServerConfig;
  security: SecurityConfig;
  output: OutputConfig;
  log_level?: 'debug' | 'info' | 'warn' | 'error';
  plugins?: string[];
}

export interface AnalyzerConfig {
  name: string;
  enabled: boolean;
  timeout?: number;
  options?: Record<string, any>;
}

export interface CollectorConfig {
  type: 'local' | 'etherscan' | 'github' | 'zip';
  source: string;
  options?: Record<string, any>;
}
