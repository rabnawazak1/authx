// src/otp/otp.module.ts
import { Module } from '@nestjs/common';
import { OtpService } from './otp.service';
import { PrismaService } from '../prisma/prisma.service';
import { MailModule } from 'src/mail/mail.module';
import { SmsModule } from 'src/sms/sms.module';

@Module({
  imports: [MailModule, SmsModule],
  providers: [OtpService, PrismaService],
  exports: [OtpService],
})
export class OtpModule {}
