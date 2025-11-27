// src/user/user.controller.ts
import { Controller, Get, Param, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { RolesGuard } from 'src/common/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';

@Controller('users')
@UseGuards(RolesGuard)
export class UserController {
  constructor(private users: UserService) {}

  @Get(':id')
  @Roles('ADMIN', 'USER')
  async getUser(@Param('id') id: string) {
    return this.users.findById(id);
  }
}
