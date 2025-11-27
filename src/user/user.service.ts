// src/user/user.service.ts
import { Injectable, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { hashString } from '../utils/hash.util';

@Injectable()
export class UserService {
  constructor(private prisma: PrismaService) {}

  async findByEmail(email: string) {
    if (!email) return null;
    return this.prisma.user.findUnique({ where: { email } });
  }

  async findByPhone(phone: string) {
    if (!phone) return null;
    return this.prisma.user.findUnique({ where: { phone } });
  }

  async findById(id: string) {
    return this.prisma.user.findUnique({ where: { id } });
  }

  async createUser(payload: {
    email?: string;
    phone?: string;
    password?: string;
    role?: 'USER' | 'ADMIN';
  }) {
    if (!payload.email && !payload.phone) {
      throw new BadRequestException('email or phone required');
    }
    const data: any = {
      email: payload.email || null,
      phone: payload.phone || null,
      role: payload.role || 'USER',
    };
    if (payload.password) {
      data.password = await hashString(payload.password);
    }
    return this.prisma.user.create({ data });
  }

  async setEmailVerified(userId: string) {
    return this.prisma.user.update({ where: { id: userId }, data: { isEmailVerified: true } });
  }
  async setPhoneVerified(userId: string) {
    return this.prisma.user.update({ where: { id: userId }, data: { isPhoneVerified: true } });
  }

  async updatePassword(userId: string, newPassword: string) {
    const hashed = await hashString(newPassword);
    return this.prisma.user.update({ where: { id: userId }, data: { password: hashed } });
  }
}
