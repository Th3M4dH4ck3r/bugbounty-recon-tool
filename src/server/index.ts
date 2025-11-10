/**
 * REST API server for Scout
 */

import express, { Request, Response, NextFunction } from 'express';
import { log } from '../utils/logger';
import { scanRoutes } from './routes/scan';
import { findingsRoutes } from './routes/findings';
import { pocRoutes } from './routes/poc';

export interface ServerOptions {
  port: number;
  host: string;
}

/**
 * Start the Scout API server
 */
export async function startServer(options: ServerOptions): Promise<void> {
  const app = express();

  // Middleware
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // CORS
  app.use((req: Request, res: Response, next: NextFunction) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
  });

  // Request logging
  app.use((req: Request, res: Response, next: NextFunction) => {
    log.debug(`${req.method} ${req.path}`);
    next();
  });

  // Health check
  app.get('/health', (req: Request, res: Response) => {
    res.json({ status: 'healthy', timestamp: new Date().toISOString() });
  });

  // API routes
  app.use('/api/scan', scanRoutes);
  app.use('/api/findings', findingsRoutes);
  app.use('/api/poc', pocRoutes);

  // 404 handler
  app.use((req: Request, res: Response) => {
    res.status(404).json({ error: 'Not found' });
  });

  // Error handler
  app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    log.error('Server error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  });

  // Start server
  return new Promise((resolve) => {
    app.listen(options.port, options.host, () => {
      log.success(`Scout API server running at http://${options.host}:${options.port}`);
      log.info('API endpoints:');
      log.info(`  POST   /api/scan - Start a new scan`);
      log.info(`  GET    /api/scan/:id - Get scan status`);
      log.info(`  GET    /api/findings - List all findings`);
      log.info(`  GET    /api/findings/:id - Get specific finding`);
      log.info(`  POST   /api/poc/:id - Generate PoC for finding`);
      log.info(`  GET    /health - Health check`);
      resolve();
    });
  });
}
