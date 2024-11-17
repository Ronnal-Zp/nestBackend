import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dto';
import { AuthGuardGuard } from './guards/auth-guard/auth-guard.guard';
import { PayloadJwt } from './interfaces/payload-jwt';
import { LoginResponse } from './interfaces/login-response';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly jwtService: JwtService
  ) {}

  @Post()
  create(@Body() CreateUserDto: CreateUserDto) {
    // console.log(CreateUserDto);
    return this.authService.create(CreateUserDto);
  }

  @Post('/login')
  login(@Body() LoginDto: LoginDto) {
    return this.authService.login(LoginDto);
  }

  @Post('/register')
  register(@Body() CreateUserDto: CreateUserDto) {
    return this.authService.register(CreateUserDto);
  }

  @UseGuards( AuthGuardGuard )
  @Get()
  findAll() {
    return this.authService.findAll();
  }

  @Get('/check-token')
  async checkToken(@Req() request: Request): Promise<LoginResponse> {
    const token = this.authService.extractTokenFromHeader(request);
    let user = null;

    if (!token) {
      throw new UnauthorizedException('Debe proporcionar el token.');
    }

    try {
      const payload = await this.jwtService.verifyAsync<PayloadJwt>(
        token, { secret: process.env.JWT_SEED }
      );
  
      const user_id = payload.id;
      user = await this.authService.findOne(user_id)  

      if(!user) throw new UnauthorizedException('No existe el usuario.');
      if(!user.isActive) throw new UnauthorizedException('El usuario esta inactivo');

    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
    
    return {
      user,
      token,
    }
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne( id );
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
