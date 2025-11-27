// src/auth/auth.service.ts
import { Injectable, BadRequestException, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserService } from '../user/user.service';
import { hashString, compareHash } from '../utils/hash.util';
import { signAccessToken, signRefreshToken, generateRandomTokenHex } from '../utils/token.util';
import { addSeconds } from 'date-fns';
import { sign } from 'jsonwebtoken';
import { MailService } from 'src/mail/mail.service';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private userService: UserService,private readonly mailService: MailService,) {}

  async register(payload: { email?: string; phone?: string; password?: string }) {
    // create user inside a transaction to ensure atomicity
    return this.prisma.$transaction(async (tx) => {
      // check uniqueness
      if (payload.email) {
        const existing = await tx.user.findUnique({ where: { email: payload.email } });
        if (existing) throw new BadRequestException('Email already in use');
      }
      if (payload.phone) {
        const existing = await tx.user.findUnique({ where: { phone: payload.phone } });
        if (existing) throw new BadRequestException('Phone already in use');
      }
      const hashed = payload.password ? await hashString(payload.password) : undefined;
      const user = await tx.user.create({
        data: {
          email: payload.email ?? null,
          phone: payload.phone ?? null,
          password: hashed ?? null,
        },
      });
      if (user.email) {
  await this.sendOtpEmail(user);
}
      return user;
    });
  }

  async validateCredentialsByEmail(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) throw new UnauthorizedException('Invalid credentials');
    const ok = await compareHash(password, user.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async validateCredentialsByPhone(phone: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { phone } });
    if (!user || !user.password) throw new UnauthorizedException('Invalid credentials');
    const ok = await compareHash(password, user.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async createTokensForUser(user: any) {
    const payload = { sub: user.id, role: user.role };
    const accessToken = signAccessToken(payload);
    const refreshToken = signRefreshToken(payload);

    // store hashed refresh token, enable rotation
    const hashed = await hashString(refreshToken);
    const expiresAt = addSeconds(new Date(), this._refreshTokenSeconds());
    // revoke old tokens? optional rotation logic will be handled during refresh
    const rt = await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: hashed,
        expiresAt,
      },
    });

    return { accessToken, refreshToken };
  }

  private _refreshTokenSeconds(): number {
    // parse e.g., '7d' or '86400s' — for simplicity default 7 days => 604800 seconds
    const env = process.env.JWT_REFRESH_EXPIRATION || '7d';
    if (env.endsWith('d')) {
      const days = parseInt(env.replace('d', ''), 10);
      return days * 24 * 3600;
    }
    if (env.endsWith('s')) {
      return parseInt(env.replace('s', ''), 10);
    }
    return 7 * 24 * 3600;
  }

  async logout(userId: string, refreshToken: string) {
    // mark refresh token as revoked
    const tokens = await this.prisma.refreshToken.findMany({ where: { userId, revoked: false } });
    for (const t of tokens) {
      // compare
      const ok = await compareHash(refreshToken, t.tokenHash);
      if (ok) {
        await this.prisma.refreshToken.update({ where: { id: t.id }, data: { revoked: true } });
        return { message: 'Logged out' };
      }
    }
    throw new BadRequestException('Refresh token not found');
  }

  async rotateRefreshToken(oldToken: string) {
    // verify old token signature
    try {
      const payload: any = sign(oldToken, process.env.JWT_REFRESH_SECRET || '');
      throw new Error('Use jwt.verify instead of sign'); // unreachable placeholder
    } catch (err) {
      // will use jwt.verify in route; rotation logic done in controller or strategy
    }
    throw new Error('Not implemented: rotateRefreshToken should be called from controller using JWT verify');
  }

  // helper: revokeAll refresh tokens for user (used in emergency)
  async revokeAllRefreshTokensForUser(userId: string) {
    await this.prisma.refreshToken.updateMany({ where: { userId, revoked: false }, data: { revoked: true } });
  }
//mail service
  async sendEmailVerification(user: any, code: string) {
    await this.mailService.sendEmailOtp({
      to: user.email,
      subject: 'Verify Your Email',
      template: 'email-verification',
      context: { name: user.name, code },
    });
  }

  async sendOtpEmail(user: any) {
  const code = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit OTP
  const expiresAt = addSeconds(new Date(), 120); // 2 minutes expiry

  // save OTP in DB (you may have otp table)
  await this.prisma.otp.create({
    data: {
      userId: user.id,
      code,
      expiresAt,
      type: 'EMAIL',
    },
  });

  // send OTP email
  await this.mailService.sendEmailOtp({
    to: user.email,
    subject: 'Verify Your Email',
    template: 'email-verification',
    context: { name: user.name || 'User', code },
  });

  return { message: 'OTP sent' };
}

}

