import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PayloadJwt } from 'src/auth/interfaces/payload-jwt';

@Injectable()
export class AuthGuardGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Debe proporcionar el token.');
    }
    try {
      const payload = await this.jwtService.verifyAsync<PayloadJwt>(
        token, { secret: process.env.JWT_SEED }
      );

      request['user_id'] = payload.id;
    } catch {
      throw new UnauthorizedException('Token invalido.');
    }

    return Promise.resolve(true);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
