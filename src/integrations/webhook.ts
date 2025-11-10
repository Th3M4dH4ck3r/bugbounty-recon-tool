/**
 * Webhook integrations for notifications
 */

import axios from 'axios';
import { logger } from '../utils/logger';
import { Finding } from '../types';

/**
 * Send webhook notification
 */
export async function sendWebhook(url: string, payload: any, headers?: Record<string, string>): Promise<void> {
  try {
    await axios.post(url, payload, { headers });
    logger.info('Webhook notification sent');
  } catch (error: any) {
    logger.error('Webhook failed:', error.message);
  }
}

/**
 * Send Slack notification
 */
export async function sendSlackNotification(webhookUrl: string, finding: Finding): Promise<void> {
  const payload = {
    text: `🚨 New Security Finding: ${finding.title}`,
    blocks: [
      {
        type: 'section',
        text: {
          type: 'mrkdwn',
          text: `*${finding.title}*\n*Severity:* ${finding.severity.toUpperCase()}\n*Contract:* ${finding.contract}`,
        },
      },
    ],
  };

  await sendWebhook(webhookUrl, payload);
}

/**
 * Send Discord notification
 */
export async function sendDiscordNotification(webhookUrl: string, finding: Finding): Promise<void> {
  const payload = {
    content: `🚨 New Security Finding`,
    embeds: [
      {
        title: finding.title,
        description: finding.description,
        color: getSeverityColor(finding.severity),
        fields: [
          { name: 'Severity', value: finding.severity.toUpperCase(), inline: true },
          { name: 'Contract', value: finding.contract, inline: true },
          { name: 'Rule ID', value: finding.rule_id, inline: true },
        ],
      },
    ],
  };

  await sendWebhook(webhookUrl, payload);
}

function getSeverityColor(severity: string): number {
  const colors: Record<string, number> = {
    critical: 0xff0000, // Red
    high: 0xff6600,    // Orange
    medium: 0xffff00,  // Yellow
    low: 0x0099ff,     // Blue
    informational: 0x808080, // Gray
  };
  return colors[severity] || 0x808080;
}
