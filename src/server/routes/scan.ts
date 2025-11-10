/**
 * Scan API routes
 */

import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

export const scanRoutes = Router();

// In-memory storage (replace with database in production)
const scans: Map<string, any> = new Map();

/**
 * POST /api/scan - Start a new scan
 */
scanRoutes.post('/', async (req: Request, res: Response) => {
  try {
    const { target, analyzers, options } = req.body;

    if (!target) {
      return res.status(400).json({ error: 'Target is required' });
    }

    const scanId = uuidv4();
    const scan = {
      id: scanId,
      target,
      analyzers: analyzers || ['static'],
      options: options || {},
      status: 'queued',
      created_at: new Date().toISOString(),
      findings: [],
    };

    scans.set(scanId, scan);

    // TODO: Implement actual scan execution in background
    // For now, just return the scan ID
    setTimeout(() => {
      const s = scans.get(scanId);
      if (s) {
        s.status = 'running';
      }
    }, 1000);

    res.status(202).json({
      scan_id: scanId,
      status: 'queued',
      message: 'Scan queued for processing',
    });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/scan/:id - Get scan status
 */
scanRoutes.get('/:id', async (req: Request, res: Response) => {
  try {
    const scanId = req.params.id;
    const scan = scans.get(scanId);

    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    res.json(scan);

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/scan - List all scans
 */
scanRoutes.get('/', async (req: Request, res: Response) => {
  try {
    const allScans = Array.from(scans.values());
    res.json({ scans: allScans, total: allScans.length });

  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});
