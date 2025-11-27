// src/sms/sms.service.ts
import { Injectable } from '@nestjs/common';
import { createTwilioClient } from './providers/twilio.provider';
import { MockSmsProvider } from './providers/mock.provider';

@Injectable()
export class SmsService {
  private provider: any;
  private useMock: boolean;

  constructor() {
    this.useMock = process.env.NODE_ENV !== 'production' || !process.env.TWILIO_ACCOUNT_SID;
    if (!this.useMock) {
      this.provider = createTwilioClient();
    } else {
      this.provider = new MockSmsProvider();
    }
  }

  async sendSmsOtp(to: string, otp: string) {
    const body = `Your Rabixx verification code is: ${otp}. It expires in ${process.env.OTP_EXPIRY_SECONDS || 120} seconds.`;
    if (this.useMock) {
      return this.provider.sendSms(to, body);
    } else {
      return this.provider.messages.create({ from: process.env.TWILIO_FROM!, to, body });
    }
  }
}
