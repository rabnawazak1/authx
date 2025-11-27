// src/main.ts
import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  app.use(helmet());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
  app.useGlobalInterceptors(new ResponseInterceptor());

  // Basic rate limiter - recommend replacing with Redis-backed limiter in prod
  app.use(
    rateLimit({
      windowMs: 60 * 1000, // 1 minute window
      max: 100, // limit each IP
    }),
  );

  await app.listen(process.env.PORT || 3000);
  console.log(`AuthX running on ${await app.getUrl()}`);
}
bootstrap();
