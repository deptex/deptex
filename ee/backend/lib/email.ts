import nodemailer from 'nodemailer';

// Initialize email transporter
// For production, you'll want to use a service like SendGrid, Resend, AWS SES, etc.
// This is a basic SMTP setup - you can configure it with your email service
let transporter: nodemailer.Transporter | null = null;

function initEmailTransporter() {
  if (transporter) return transporter;

  // Check if email is configured
  const emailUser = process.env.EMAIL_USER;
  const emailPassword = process.env.EMAIL_PASSWORD;
  const emailFrom = process.env.EMAIL_FROM || emailUser || 'noreply@deptex.app';

  if (!emailUser || !emailPassword) {
    console.warn('Email not configured. Missing:', {
      user: !emailUser,
      password: !emailPassword,
    });
    console.warn('Invitation emails will not be sent.');
    return null;
  }

  // Use Gmail service (simpler and more reliable)
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: emailUser,
      pass: emailPassword.trim(), // Trim any whitespace just in case
    },
  });

  // Test the connection asynchronously (don't block initialization)
  transporter.verify().then(() => {
    console.log('✅ Email transporter verified successfully - Gmail connection works!');
  }).catch((verifyError: any) => {
    console.error('❌ Email transporter verification failed:', verifyError.message);
    console.error('This means the credentials are incorrect or Gmail is blocking the connection.');
    console.error('Please check:');
    console.error('1. Is 2-Step Verification enabled on the Gmail account?');
    console.error('2. Was the App Password generated for the correct account?');
    console.error('3. Did you copy the App Password correctly (16 characters, no spaces)?');
  });

  console.log('Email transporter initialized with Gmail service');
  return transporter;
}

/**
 * Send a generic email. Uses same SMTP config as invitation emails (EMAIL_USER, EMAIL_PASSWORD, EMAIL_FROM).
 * No-op if email is not configured.
 */
export async function sendEmail(options: {
  to: string | string[];
  subject: string;
  text?: string;
  html?: string;
  from?: string;
}): Promise<{ sent: boolean; messageId?: string; error?: string }> {
  const transporter = initEmailTransporter();
  if (!transporter) {
    return { sent: false, error: 'Email not configured' };
  }
  const to = Array.isArray(options.to) ? options.to.join(', ') : options.to;
  const from = options.from || process.env.EMAIL_FROM || process.env.EMAIL_USER || 'noreply@deptex.app';
  try {
    const result = await transporter.sendMail({
      from,
      to,
      subject: options.subject,
      text: options.text,
      html: options.html,
    });
    return { sent: true, messageId: result.messageId };
  } catch (error: any) {
    console.error('sendEmail error:', error?.message);
    return { sent: false, error: error?.message };
  }
}

export async function sendInvitationEmail(
  email: string,
  organizationName: string,
  inviterName: string,
  inviteLink: string,
  role: string,
  teamName?: string
) {
  const emailTransporter = initEmailTransporter();
  
  if (!emailTransporter) {
    console.log('Email not configured. Skipping email send.');
    console.log('Invite link:', inviteLink);
    return;
  }

  const html = `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Organization Invitation</title>
    </head>
    <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
      <div style="background: linear-gradient(135deg, #025230 0%, #4CAF50 100%); padding: 30px; text-align: center; border-radius: 8px 8px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">You've been invited!</h1>
      </div>
      <div style="background: #ffffff; padding: 30px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px;">
        <p style="font-size: 16px; margin-bottom: 20px;">
          <strong>${inviterName}</strong> has invited you to join <strong>${organizationName}</strong> as a <strong>${role}</strong>${teamName ? ` and be part of the <strong>${teamName}</strong> team` : ''}.
        </p>
        <p style="font-size: 14px; color: #6b7280; margin-bottom: 30px;">
          Click the button below to accept the invitation and join the organization${teamName ? ` and ${teamName} team` : ''}.
        </p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${inviteLink}" style="display: inline-block; background: #025230; color: white; padding: 12px 30px; text-decoration: none; border-radius: 6px; font-weight: 600; font-size: 16px;">
            Accept Invitation
          </a>
        </div>
        <p style="font-size: 12px; color: #9ca3af; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 20px;">
          If the button doesn't work, copy and paste this link into your browser:<br>
          <a href="${inviteLink}" style="color: #025230; word-break: break-all;">${inviteLink}</a>
        </p>
        <p style="font-size: 12px; color: #9ca3af; margin-top: 20px;">
          This invitation will expire in 7 days.
        </p>
      </div>
    </body>
    </html>
  `;

  const text = `
You've been invited!

${inviterName} has invited you to join ${organizationName} as a ${role}${teamName ? ` and be part of the ${teamName} team` : ''}.

Click the link below to accept the invitation:
${inviteLink}

This invitation will expire in 7 days.
  `;

  try {
    console.log(`Attempting to send invitation email to ${email}...`);
    const result = await emailTransporter.sendMail({
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER || 'noreply@deptex.app',
      to: email,
      subject: `Invitation to join ${organizationName} on Deptex`,
      html,
      text,
    });
    console.log(`✅ Invitation email sent successfully to ${email}`);
    console.log('Email result:', result.messageId);
  } catch (error: any) {
    console.error('❌ Error sending invitation email:', error);
    console.error('Error details:', {
      message: error.message,
      code: error.code,
      command: error.command,
      response: error.response,
    });
    throw error;
  }
}

