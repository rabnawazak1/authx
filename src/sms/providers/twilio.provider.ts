// src/sms/providers/twilio.provider.ts
import { Twilio } from 'twilio';

export function createTwilioClient() {
  const sid = process.env.TWILIO_ACCOUNT_SID!;
  const token = process.env.TWILIO_AUTH_TOKEN!;
  return new Twilio(sid, token);
}
