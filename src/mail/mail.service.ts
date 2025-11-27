import { Injectable, Logger } from '@nestjs/common';
import nodemailer from 'nodemailer';
import hbs from 'nodemailer-express-handlebars';
import * as path from 'path';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailService.name);

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: process.env.MAIL_HOST,
      port: parseInt(process.env.MAIL_PORT || '587', 10),
      secure: process.env.MAIL_SECURE === 'true',
      auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS,
      },
    });

    // Attach Handlebars template engine
    this.transporter.use(
      'compile',
      hbs({
        viewEngine: {
          partialsDir: path.resolve('./src/mail/templates/'),
          defaultLayout: false,
        },
        viewPath: path.resolve('./src/mail/templates/'),
        extName: '.hbs',
      }),
    );
  }

  async sendMail(options: {
    to: string;
    subject: string;
    template?: string;
    context?: Record<string, any>;
    text?: string;
    html?: string;
  }) {
    try {
      const info = await this.transporter.sendMail({
        from: process.env.MAIL_FROM!,
        to: options.to,
        subject: options.subject,
        text: options.text,
        html: options.html,
        template: options.template, // template filename without .hbs
        context: options.context,   // variables for template
      });
      this.logger.log(`Mail sent: ${info.messageId}`);
    } catch (err) {
      this.logger.error('Error sending email', err);
      throw err;
    }
  }

  // src/mail/mail.service.ts
// async sendEmailOtp(options: {
//   to: string;
//   subject: string;
//   template: string;
//   context: Record<string, any>;
// }) {
//   return this.sendMail({
//     to: options.to,
//     subject: options.subject,
//     template: options.template,
//     context: options.context,
//   });
// }

async sendEmailOtp(options: { to: string; subject: string; template: string; context: any }) {
  const html = this.renderTemplate(options.template, options.context);
  await this.sendMail({ to: options.to, subject: options.subject, html });
}

private renderTemplate(template: string, context: any) {
  // simple string interpolation for now
  if (template === 'email-verification') {
    return `<p>Hello ${context.name},</p>
            <p>Your OTP is <b>${context.code}</b></p>
            <p>This code will expire in 10 minutes.</p>`;
  }
  return '';
}

}
