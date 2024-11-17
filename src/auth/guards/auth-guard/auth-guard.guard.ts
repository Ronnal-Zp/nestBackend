import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PayloadJwt } from 'src/auth/interfaces/payload-jwt';
import { AuthService } from '../../auth.service';

@Injectable()
export class AuthGuardGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private authService: AuthService
  ) {}
  
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.authService.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('Debe proporcionar el token.');
    }

    try {
      const payload = await this.jwtService.verifyAsync<PayloadJwt>(
        token, { secret: process.env.JWT_SEED }
      );

      const user_id = payload.id;
      const user = await this.authService.findOne(user_id)

      if(!user) throw new UnauthorizedException('No existe el usuario.');
      if(!user.isActive) throw new UnauthorizedException('El usuario esta inactivo');

      request['user_id'] = user_id;
    } catch(error) {
      throw new UnauthorizedException(error.message);
    }

    return Promise.resolve(true);
  }
}
