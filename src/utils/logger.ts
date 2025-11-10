/**
 * Logging utility using Winston
 */

import winston from 'winston';
import chalk from 'chalk';

const { combine, timestamp, printf, colorize, errors } = winston.format;

// Custom format for console output
const consoleFormat = printf(({ level, message, timestamp, stack }: any) => {
  const ts = new Date(timestamp as string).toLocaleTimeString();
  if (stack) {
    return `${chalk.gray(ts)} ${level}: ${message}\n${chalk.gray(stack)}`;
  }
  return `${chalk.gray(ts)} ${level}: ${message}`;
});

// Create the logger instance
export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(
    errors({ stack: true }),
    timestamp()
  ),
  transports: [
    // Console transport with colors
    new winston.transports.Console({
      format: combine(
        colorize(),
        consoleFormat
      ),
    }),
    // File transport for errors
    new winston.transports.File({
      filename: 'logs/error.log',
      level: 'error',
      format: combine(
        timestamp(),
        winston.format.json()
      ),
    }),
    // File transport for all logs
    new winston.transports.File({
      filename: 'logs/combined.log',
      format: combine(
        timestamp(),
        winston.format.json()
      ),
    }),
  ],
});

// Convenience methods with chalk formatting
export const log = {
  info: (message: string, ...args: any[]) => {
    logger.info(message, ...args);
  },
  success: (message: string, ...args: any[]) => {
    logger.info(chalk.green('✓ ') + message, ...args);
  },
  warn: (message: string, ...args: any[]) => {
    logger.warn(chalk.yellow('⚠ ') + message, ...args);
  },
  error: (message: string, ...args: any[]) => {
    logger.error(chalk.red('✗ ') + message, ...args);
  },
  debug: (message: string, ...args: any[]) => {
    logger.debug(chalk.gray('→ ') + message, ...args);
  },
  finding: (severity: string, message: string) => {
    const severityColor = {
      critical: chalk.bgRed.white.bold,
      high: chalk.red.bold,
      medium: chalk.yellow.bold,
      low: chalk.blue,
      informational: chalk.gray,
    }[severity.toLowerCase()] || chalk.white;

    logger.info(`${severityColor(`[${severity.toUpperCase()}]`)} ${message}`);
  },
};

export default logger;
