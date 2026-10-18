'use strict';

/**
 * VaultBase — Email Service
 *
 * For demo: logs OTP to the console (no real SMTP needed).
 * For production: configure SMTP_* env vars (SendGrid, SES, Gmail, etc.)
 */

const nodemailer = require('nodemailer');

let transporter = null;
const testMailbox = new Map(); // toEmail -> { otp, timestamp, subject }

function maskEmail(email) {
  if (!email || !email.includes('@')) return email || '';
  const [user, domain] = email.split('@');
  const masked = user[0] + '***' + (user.length > 1 ? user.slice(-1) : '');
  return `${masked}@${domain}`;
}

function getTransporter() {
  if (transporter) return transporter;

  // If SMTP env vars provided, use real SMTP
  if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
    const isGmail = process.env.SMTP_HOST.includes('gmail.com');
    
    transporter = nodemailer.createTransport(isGmail ? {
      service: 'gmail',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      }
    } : {
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_SECURE === 'true',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      }
    });
    console.log(`[Email] Transport configured via SMTP (${isGmail ? 'Gmail' : process.env.SMTP_HOST})`);
  } else {
    // Development / Test console mode — never logs raw OTP in logs
    transporter = {
      sendMail: async (opts) => {
        console.log(`[Email] 📧 Outbound verification message dispatched to ${maskEmail(opts.to)} [REDACTED]`);
        return { messageId: 'dev-' + Date.now() };
      }
    };
    console.log('[Email] Development email transport initialized (secure mode)');
  }

  return transporter;
}

/**
 * Send OTP email to the given address.
 * @param {string} to    - Recipient email
 * @param {string} otp   - 6-digit code
 * @param {string} email - User email (for greeting)
 */
async function sendOTPEmail(to, otp, email) {
  // In test environment, capture for automated test assertions
  if (process.env.NODE_ENV === 'test') {
    testMailbox.set(to.toLowerCase().trim(), { otp, timestamp: Date.now() });
  }

  const t = getTransporter();
  const subject = 'Your VaultBase Verification Code';
  const text = `
VaultBase — One-Time Passcode
──────────────────────────────

Hello ${email},

Your verification code is:

    ${otp}

This code expires in 5 minutes.

Do not share this code with anyone.
If you did not request this, please ignore this email.

— VaultBase Security Team
  `.trim();

  const html = `
<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, sans-serif; background:#0f0f13; color:#e2e8f0; padding:40px; margin:0;">
  <div style="max-width:480px; margin:0 auto; background:#1a1a2e; border-radius:16px; overflow:hidden; border:1px solid #2d2d4e;">
    <div style="background:linear-gradient(135deg,#6366f1,#8b5cf6); padding:32px; text-align:center;">
      <h1 style="margin:0; color:#fff; font-size:24px; letter-spacing:-0.5px;">🔐 VaultBase</h1>
      <p style="margin:8px 0 0; color:rgba(255,255,255,0.8); font-size:14px;">Multi-Factor Authentication</p>
    </div>
    <div style="padding:32px;">
      <p style="margin:0 0 24px; color:#94a3b8;">Hello <strong style="color:#e2e8f0;">${email}</strong>,</p>
      <p style="margin:0 0 24px; color:#94a3b8;">Your one-time verification code is:</p>
      <div style="background:#0f0f13; border:2px solid #6366f1; border-radius:12px; padding:24px; text-align:center; margin:0 0 24px;">
        <span style="font-size:40px; font-weight:700; letter-spacing:12px; color:#a5b4fc; font-family:monospace;">${otp}</span>
      </div>
      <p style="margin:0 0 8px; color:#64748b; font-size:13px;">⏱ Expires in <strong>5 minutes</strong></p>
      <p style="margin:0; color:#64748b; font-size:13px;">🔒 Never share this code with anyone.</p>
    </div>
    <div style="padding:16px 32px; border-top:1px solid #2d2d4e; text-align:center;">
      <p style="margin:0; color:#475569; font-size:12px;">© VaultBase Security · If you didn't request this, ignore this email.</p>
    </div>
  </div>
</body>
</html>
  `.trim();

  await t.sendMail({ from: '"VaultBase" <noreply@vaultbase.io>', to, subject, text, html });
}

// ── Test Mailbox Helpers (Test-only hook) ─────────────────────────────────────
function getLastSentOTPForTest(toEmail) {
  if (process.env.NODE_ENV !== 'test') return null;
  const entry = testMailbox.get(toEmail.toLowerCase().trim());
  return entry ? entry.otp : null;
}

function clearTestMailbox() {
  testMailbox.clear();
}

module.exports = {
  sendOTPEmail,
  getLastSentOTPForTest,
  clearTestMailbox,
};
