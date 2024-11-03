import { Module } from "@nestjs/common"
import { AuthService } from "./auth.service"
import { AuthController } from "./auth.controller"
import { PrismaService } from "src/prisma.service"
import { JwtModule, JwtService } from "@nestjs/jwt"

@Module({
	imports: [
		JwtModule.register({
			global: true,
			secret: process.env.JWT_SECRET_KEY
		})
	],
	providers: [AuthService, PrismaService, JwtService],
	controllers: [AuthController]
})
export class AuthModule {}
