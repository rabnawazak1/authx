// src/otp/otp.service.ts
import { Injectable, BadRequestException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { generateNumericOTP, otpExpirySeconds } from '../utils/otp.util';
import { hashString, compareHash } from '../utils/hash.util';
import { subSeconds, addSeconds } from 'date-fns';
import { MailService } from 'src/mail/mail.service';
import { SmsService } from 'src/sms/sms.service';

@Injectable()
export class OtpService {
  constructor(
    private prisma: PrismaService,
    private mail: MailService,
    private sms: SmsService,
  ) {}

  private OTP_MAX_ATTEMPTS = parseInt(process.env.OTP_MAX_ATTEMPTS || '3', 10);

  async sendEmailOtp(userId: string, email: string) {
    const otp = generateNumericOTP(6);
    const otpHash = await hashString(otp);
    const expiresAt = addSeconds(new Date(), otpExpirySeconds());

    // invalidate previous active OTPs for email by marking used or deleting (we mark used)
    await this.prisma.emailOTP.updateMany({
      where: { userId, used: false, expiresAt: { gt: new Date() } },
      data: { used: true },
    });

    await this.prisma.emailOTP.create({
      data: { userId, otpHash, expiresAt },
    });

    // send email via MailService
    await this.mail.sendEmailOtp(email, otp);

    return { message: 'OTP sent to email' };
  }

  async sendPhoneOtp(userId: string, phone: string) {
    const otp = generateNumericOTP(6);
    const otpHash = await hashString(otp);
    const expiresAt = addSeconds(new Date(), otpExpirySeconds());

    await this.prisma.phoneOTP.updateMany({
      where: { userId, used: false, expiresAt: { gt: new Date() } },
      data: { used: true },
    });

    await this.prisma.phoneOTP.create({
      data: { userId, otpHash, expiresAt },
    });

    await this.sms.sendSmsOtp(phone, otp);

    return { message: 'OTP sent to phone' };
  }

  async verifyEmailOtp(userId: string, otp: string) {
    const record = await this.prisma.emailOTP.findFirst({
      where: { userId, used: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    });
    if (!record) throw new BadRequestException('No active OTP found or expired');
    if (record.attempts >= this.OTP_MAX_ATTEMPTS) {
      throw new ForbiddenException('Max OTP attempts exceeded');
    }
    const ok = await compareHash(otp, record.otpHash);
    if (!ok) {
      await this.prisma.emailOTP.update({ where: { id: record.id }, data: { attempts: { increment: 1 } } });
      throw new BadRequestException('Invalid OTP');
    }
    await this.prisma.emailOTP.update({ where: { id: record.id }, data: { used: true } });
    await this.prisma.user.update({ where: { id: userId }, data: { isEmailVerified: true } });
    return { message: 'Email verified' };
  }

  async verifyPhoneOtp(userId: string, otp: string) {
    const record = await this.prisma.phoneOTP.findFirst({
      where: { userId, used: false, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    });
    if (!record) throw new BadRequestException('No active OTP found or expired');
    if (record.attempts >= this.OTP_MAX_ATTEMPTS) {
      throw new ForbiddenException('Max OTP attempts exceeded');
    }
    const ok = await compareHash(otp, record.otpHash);
    if (!ok) {
      await this.prisma.phoneOTP.update({ where: { id: record.id }, data: { attempts: { increment: 1 } } });
      throw new BadRequestException('Invalid OTP');
    }
    await this.prisma.phoneOTP.update({ where: { id: record.id }, data: { used: true } });
    await this.prisma.user.update({ where: { id: userId }, data: { isPhoneVerified: true } });
    return { message: 'Phone verified' };
  }

  // OTP for passwordless login: create OTP for existing user and return a temporary token? We'll send OTP and rely on verify flow to create session.
}
