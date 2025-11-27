// src/utils/otp.util.ts
export function generateNumericOTP(length = 6): string {
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += Math.floor(Math.random() * 10).toString();
  }
  return otp;
}

export function otpExpirySeconds(): number {
  const env = process.env.OTP_EXPIRY_SECONDS;
  return env ? parseInt(env, 10) : 120;
}
