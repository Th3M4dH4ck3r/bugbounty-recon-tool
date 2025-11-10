/**
 * Configurable rule engine for loading and executing custom rules
 */

import fs from 'fs-extra';
import yaml from 'js-yaml';
import { logger } from '../utils/logger';
import { Rule, Severity } from '../types';

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: string;
  pattern?: string;
  patterns?: string[];
  antipattern?: string;
  recommendation: string;
  references?: string[];
  enabled?: boolean;
}

/**
 * Load rules from a YAML or JSON file
 */
export async function loadRules(filePath: string): Promise<Rule[]> {
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    let ruleDefinitions: RuleDefinition[];

    if (filePath.endsWith('.yaml') || filePath.endsWith('.yml')) {
      ruleDefinitions = yaml.load(content) as RuleDefinition[];
    } else if (filePath.endsWith('.json')) {
      ruleDefinitions = JSON.parse(content);
    } else {
      throw new Error('Unsupported rule file format. Use .yaml, .yml, or .json');
    }

    return ruleDefinitions.map(convertToRule);
  } catch (error: any) {
    logger.error(`Failed to load rules from ${filePath}:`, error.message);
    throw error;
  }
}

/**
 * Convert rule definition to executable rule
 */
function convertToRule(def: RuleDefinition): Rule {
  return {
    id: def.id,
    name: def.name,
    description: def.description,
    severity: def.severity,
    category: def.category,
    recommendation: def.recommendation,
    references: def.references,
    enabled: def.enabled !== false,
    check: createCheckFunction(def),
  };
}

/**
 * Create a check function from rule definition
 */
function createCheckFunction(def: RuleDefinition): (context: any) => boolean {
  return (context: any) => {
    const code = context.code || '';

    // Single pattern matching
    if (def.pattern) {
      const regex = new RegExp(def.pattern, 'i');
      const matches = regex.test(code);

      // If antipattern is defined, exclude matches that also match antipattern
      if (matches && def.antipattern) {
        const antiRegex = new RegExp(def.antipattern, 'i');
        return !antiRegex.test(code);
      }

      return matches;
    }

    // Multiple patterns - all must match
    if (def.patterns && def.patterns.length > 0) {
      const allMatch = def.patterns.every(pattern => {
        const regex = new RegExp(pattern, 'i');
        return regex.test(code);
      });

      // Check antipattern
      if (allMatch && def.antipattern) {
        const antiRegex = new RegExp(def.antipattern, 'i');
        return !antiRegex.test(code);
      }

      return allMatch;
    }

    return false;
  };
}

/**
 * Validate rule definition
 */
export function validateRule(def: RuleDefinition): boolean {
  const required = ['id', 'name', 'description', 'severity', 'category', 'recommendation'];

  for (const field of required) {
    if (!(field in def)) {
      logger.error(`Rule missing required field: ${field}`);
      return false;
    }
  }

  const validSeverities: Severity[] = ['critical', 'high', 'medium', 'low', 'informational'];
  if (!validSeverities.includes(def.severity)) {
    logger.error(`Invalid severity: ${def.severity}. Must be one of: ${validSeverities.join(', ')}`);
    return false;
  }

  if (!def.pattern && !def.patterns) {
    logger.error('Rule must have either pattern or patterns field');
    return false;
  }

  return true;
}

/**
 * Create a rule file template
 */
export function createRuleTemplate(): RuleDefinition[] {
  return [
    {
      id: 'CUSTOM-001',
      name: 'Custom Vulnerability Pattern',
      description: 'Description of what this rule detects',
      severity: 'high',
      category: 'custom',
      pattern: 'regex-pattern-to-match',
      antipattern: 'regex-pattern-to-exclude',
      recommendation: 'How to fix this issue',
      references: [
        'https://example.com/reference',
      ],
      enabled: true,
    },
  ];
}
