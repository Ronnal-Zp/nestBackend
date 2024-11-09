import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';

import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) private userModel: Model<User>
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


  async login(LoginDto: LoginDto): Promise<User> {
    const { email, password } = LoginDto;
    const user = await this.userModel.findOne({ email })
    
    if(!user) {
      throw new UnauthorizedException('Credenciales no validas.');  
    }

    if(!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no validas.');
    }

    const { password:_, ...rest } = user.toJSON();

    return { ...rest };
  }


  findAll() {
    return `This action returns all auth`;
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
}
