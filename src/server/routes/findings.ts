/**
 * Findings API routes
 */

import { Router, Request, Response } from 'express';
import { readJson, exists } from '../../utils/file-utils';
import { Finding } from '../../types';

export const findingsRoutes = Router();

/**
 * GET /api/findings - List all findings
 */
findingsRoutes.get('/', async (req: Request, res: Response) => {
  try {
    const findingsPath = './reports/findings.json';

    if (!await exists(findingsPath)) {
      return res.json({ findings: [], total: 0 });
    }

    const findings: Finding[] = await readJson(findingsPath);

    // Apply filters
    let filtered = findings;

    if (req.query.severity) {
      filtered = filtered.filter(f => f.severity === req.query.severity);
    }

    if (req.query.contract) {
      filtered = filtered.filter(f => f.contract === req.query.contract);
    }

    res.json({ findings: filtered, total: filtered.length });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/findings/:id - Get specific finding
 */
findingsRoutes.get('/:id', async (req: Request, res: Response) => {
  try {
    const findingsPath = './reports/findings.json';

    if (!await exists(findingsPath)) {
      return res.status(404).json({ error: 'Findings not found' });
    }

    const findings: Finding[] = await readJson(findingsPath);
    const finding = findings.find(f => f.id === req.params.id);

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    res.json(finding);

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});
