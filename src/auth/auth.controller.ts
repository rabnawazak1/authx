// src/auth/auth.controller.ts
import {
  Body,
  Controller,
  Post,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  BadRequestException,
  UseGuards,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { OtpDto } from './dto/otp.dto';
import { ForgotDto, ResetDto } from './dto/forgot-reset.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { OtpService } from '../otp/otp.service';
import { UserService } from '../user/user.service';
import { PrismaService } from '../prisma/prisma.service';
import { hashString, compareHash } from '../utils/hash.util';
import { signAccessToken, signRefreshToken } from '../utils/token.util';
import { addSeconds } from 'date-fns';
import * as jwt from 'jsonwebtoken';

@Controller('auth')
export class AuthController {
  constructor(
    private auth: AuthService,
    private otp: OtpService,
    private userService: UserService,
    private prisma: PrismaService,
  ) {}

  @Post('register')
  async register(@Body() dto: RegisterDto) {
    const user = await this.auth.register(dto);
    // send initial OTP(s) based on provided identifiers
    if (dto.email) await this.otp.sendEmailOtp(user.id, dto.email);
    if (dto.phone) await this.otp.sendPhoneOtp(user.id, dto.phone);
    return { id: user.id, email: user.email, phone: user.phone };
  }

  @Post('verify/email')
  async verifyEmail(@Body() body: OtpDto) {
    if (!body.email) throw new BadRequestException('email required');
    // find user
    const user = await this.userService.findByEmail(body.email);
    if (!user) throw new BadRequestException('User not found');
    return this.otp.verifyEmailOtp(user.id, body.otp);
  }

  @Post('verify/phone')
  async verifyPhone(@Body() body: OtpDto) {
    if (!body.phone) throw new BadRequestException('phone required');
    const user = await this.userService.findByPhone(body.phone);
    if (!user) throw new BadRequestException('User not found');
    return this.otp.verifyPhoneOtp(user.id, body.otp);
  }

  @Post('resend/email')
  async resendEmail(@Body() body: { email: string }) {
    const user = await this.userService.findByEmail(body.email);
    if (!user) throw new BadRequestException('User not found');
    return this.otp.sendEmailOtp(user.id, body.email);
  }

  @Post('resend/phone')
  async resendPhone(@Body() body: { phone: string }) {
    const user = await this.userService.findByPhone(body.phone);
    if (!user) throw new BadRequestException('User not found');
    return this.otp.sendPhoneOtp(user.id, body.phone);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() dto: LoginDto) {
    if (dto.email) {
      const user = await this.auth.validateCredentialsByEmail(dto.email, dto.password);
      const tokens = await this.auth.createTokensForUser(user);
      return { user: { id: user.id, email: user.email, phone: user.phone }, ...tokens };
    } else if (dto.phone) {
      const user = await this.auth.validateCredentialsByPhone(dto.phone, dto.password);
      const tokens = await this.auth.createTokensForUser(user);
      return { user: { id: user.id, email: user.email, phone: user.phone }, ...tokens };
    }
    throw new BadRequestException('email or phone required for password login');
  }

  @Post('login/otp')
  async loginOtp(@Body() body: { email?: string; phone?: string }) {
    // For passwordless login, send OTP to existing user
    if (body.email) {
      const user = await this.userService.findByEmail(body.email);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.sendEmailOtp(user.id, body.email);
      return { message: 'OTP sent to email' };
    }
    if (body.phone) {
      const user = await this.userService.findByPhone(body.phone);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.sendPhoneOtp(user.id, body.phone);
      return { message: 'OTP sent to phone' };
    }
    throw new BadRequestException('email or phone required');
  }

  @Post('login/otp/verify')
  async loginOtpVerify(@Body() dto: OtpDto) {
    // verify OTP and issue tokens
    let user;
    if (dto.email) {
      user = await this.userService.findByEmail(dto.email);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.verifyEmailOtp(user.id, dto.otp);
    } else if (dto.phone) {
      user = await this.userService.findByPhone(dto.phone);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.verifyPhoneOtp(user.id, dto.otp);
    } else {
      throw new BadRequestException('email or phone required');
    }
    // At this point email/phone marked verified if not already
    const tokens = await this.auth.createTokensForUser(user);
    return { user: { id: user.id, email: user.email, phone: user.phone }, ...tokens };
  }

  @Post('forgot')
  async forgot(@Body() dto: ForgotDto) {
    if (dto.email) {
      const user = await this.userService.findByEmail(dto.email);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.sendEmailOtp(user.id, dto.email);
      return { message: 'OTP sent to email' };
    }
    if (dto.phone) {
      const user = await this.userService.findByPhone(dto.phone);
      if (!user) throw new BadRequestException('User not found');
      await this.otp.sendPhoneOtp(user.id, dto.phone);
      return { message: 'OTP sent to phone' };
    }
    throw new BadRequestException('email or phone required');
  }

  @Post('reset')
  async reset(@Body() dto: ResetDto) {
    // We expect dto.token to be validated via OTP flows; here we accept OTP verification first then set password
    // For simplicity, require that user has verified OTP in prior route (or call verify endpoint before reset)
    // In practice include OTP id or short lived token that maps to user
    throw new BadRequestException('Use OTP verify endpoint then call password reset with authenticated user.');
  }

  @Post('refresh')
  async refresh(@Body() dto: RefreshTokenDto) {
    const rawToken = dto.refreshToken;
    if (!rawToken) throw new BadRequestException('refreshToken required');

    let payload: any;
    try {
      payload = jwt.verify(rawToken, process.env.JWT_REFRESH_SECRET || '');
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    const userId = payload.sub;
    // Find refresh tokens for user and compare hash
    const tokens = await this.prisma.refreshToken.findMany({ where: { userId, revoked: false } });
    let matched = null;
    for (const t of tokens) {
      const ok = await compareHash(rawToken, t.tokenHash);
      if (ok) {
        matched = t;
        break;
      }
    }
    if (!matched) throw new UnauthorizedException('Refresh token not recognized');

    // rotate: revoke old, create new refresh token
    await this.prisma.refreshToken.update({ where: { id: matched.id }, data: { revoked: true } });

    const newAccessToken = signAccessToken({ sub: userId, role: payload.role });
    const newRefreshToken = signRefreshToken({ sub: userId, role: payload.role });
    const newHash = await hashString(newRefreshToken);
    const expiresAt = addSeconds(new Date(), 7 * 24 * 3600);

    await this.prisma.refreshToken.create({
      data: { userId, tokenHash: newHash, expiresAt },
    });

    return { accessToken: newAccessToken, refreshToken: newRefreshToken };
  }

  @Post('logout')
  async logout(@Body() dto: RefreshTokenDto) {
    // expects refresh token to identify which token to revoke
    const rawToken = dto.refreshToken;
    let payload: any;
    try {
      payload = jwt.verify(rawToken, process.env.JWT_REFRESH_SECRET || '');
    } catch (err) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    // find token and revoke
    const userId = payload.sub;
    const tokens = await this.prisma.refreshToken.findMany({ where: { userId, revoked: false } });
    for (const t of tokens) {
      const ok = await compareHash(rawToken, t.tokenHash);
      if (ok) {
        await this.prisma.refreshToken.update({ where: { id: t.id }, data: { revoked: true } });
        return { message: 'Logged out' };
      }
    }
    throw new BadRequestException('Refresh token not found');
  }
}
