// src/auth/dto/forgot-reset.dto.ts
import { IsEmail, IsOptional, IsPhoneNumber, IsString, Matches, MinLength } from 'class-validator';

export class ForgotDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
  message: 'Invalid phone number format',
})
phone?: string;

}

export class ResetDto {
  @IsString()
  token!: string; // Could be OTP token ID or similar - we use OTP flows

  @IsString()
  @MinLength(8)
  newPassword!: string;
}
