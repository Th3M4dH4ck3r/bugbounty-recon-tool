/**
 * PoC API routes
 */

import { Router, Request, Response } from 'express';
import { readJson, readFile, exists } from '../../utils/file-utils';
import { Finding } from '../../types';
import { generatePoc } from '../../poc';

export const pocRoutes = Router();

/**
 * POST /api/poc/:id - Generate PoC for a finding
 */
pocRoutes.post('/:id', async (req: Request, res: Response) => {
  try {
    const findingId = req.params.id;
    const { type = 'hardhat', outputDir = './pocs' } = req.body;

    // Load finding
    const findingsPath = './reports/findings.json';
    if (!await exists(findingsPath)) {
      return res.status(404).json({ error: 'Findings not found' });
    }

    const findings: Finding[] = await readJson(findingsPath);
    const finding = findings.find(f => f.id === findingId);

    if (!finding) {
      return res.status(404).json({ error: 'Finding not found' });
    }

    // Generate PoC
    const poc = await generatePoc(finding, { outputDir, type });

    res.json({
      success: true,
      poc,
      finding_id: findingId,
    });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/poc/:id - Get PoC for a finding
 */
pocRoutes.get('/:id', async (req: Request, res: Response) => {
  try {
    const findingId = req.params.id;

    // Load finding
    const findingsPath = './reports/findings.json';
    if (!await exists(findingsPath)) {
      return res.status(404).json({ error: 'Findings not found' });
    }

    const findings: Finding[] = await readJson(findingsPath);
    const finding = findings.find(f => f.id === findingId);

    if (!finding || !finding.poc) {
      return res.status(404).json({ error: 'PoC not found' });
    }

    // Read PoC content
    const pocContent = await readFile(finding.poc.path);

    res.json({
      poc: finding.poc,
      content: pocContent,
    });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});
