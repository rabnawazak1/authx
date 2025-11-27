// src/auth/dto/login.dto.ts
import { IsEmail, IsOptional, IsPhoneNumber, IsString, Matches, MinLength } from 'class-validator';

export class LoginDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
  message: 'Invalid phone number format',
})
phone?: string;


  @IsString()
  @MinLength(8)
  password!: string;
}
