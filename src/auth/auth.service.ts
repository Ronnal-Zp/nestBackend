import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcryptjs from 'bcryptjs';

import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dto';
import { PayloadJwt } from './interfaces/payload-jwt';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(CreateUserDto: CreateUserDto): Promise<User> {
    try {
      
      const { password, ...userData } = CreateUserDto;
      
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });

      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();

      return user;
    } catch (error) {
        if(error.code == 11000) {
          throw new BadRequestException(`¡${CreateUserDto.email} ya existe!`);
        }

        throw new InternalServerErrorException('¡Algo grave ocurrio!');
    }

  }

  async login(LoginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = LoginDto;
    const user = await this.userModel.findOne({ email })
    
    if(!user) {
      throw new UnauthorizedException('Credenciales no validas.');  
    }

    if(!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no validas.');
    }

    const { password:_, ...rest } = user.toJSON();

    return { 
      user: rest, 
      token: this.getJwtToken({ id: user.id }) 
    };
  }

  async register(CreateUserDto: CreateUserDto): Promise<LoginResponse> {

    const user = await this.create(CreateUserDto);
    const token = this.getJwtToken({id: user._id })

    return {
      user,
      token
    }
  }

  findAll() {
    return this.userModel.find();
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: PayloadJwt): string {
    const token = this.jwtService.sign(payload);
    return token;
  }

}
