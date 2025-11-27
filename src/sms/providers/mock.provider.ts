// src/sms/mock.provider.ts
export class MockSmsProvider {
  async sendSms(to: string, body: string) {
    // In dev log only
    console.log(`[MockSms] to=${to} body=${body}`);
    return { sid: 'mock-sid' };
  }
}
