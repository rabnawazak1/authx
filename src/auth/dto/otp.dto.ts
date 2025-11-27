// src/auth/dto/otp.dto.ts
import { IsString, IsNotEmpty, IsOptional, IsEmail, IsPhoneNumber, Matches } from 'class-validator';

export class OtpDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
  message: 'Invalid phone number format',
})
phone?: string;


  @IsString()
  @IsNotEmpty()
  otp!: string;
}
