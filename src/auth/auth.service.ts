import { Injectable, UnauthorizedException } from "@nestjs/common"
import { JwtService } from "@nestjs/jwt"
import { Prisma, Users } from "@prisma/client"
import { isEmail, minLength } from "class-validator"
import { PrismaService } from "src/prisma.service"

@Injectable()
export class AuthService {
	constructor(
		private readonly prisma: PrismaService,
		private readonly jwtService: JwtService
	) {}

	async reg(data: Prisma.UsersCreateInput): Promise<Users> {
		const { email, password } = data

		const user = await this.getUser({ email })

		// Validation
		if (user) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "This Email is already in use"
			})
		}
		if (!isEmail(email)) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Invalid email"
			})
		}
		if (!minLength(password, 6)) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Password cannot be less then 6 characters"
			})
		}

		return this.prisma.users.create({ data })
	}

	async login(dto: { email: string; password: string }): Promise<{
		accessToken: string
		refreshToken: string
	}> {
		const { email, password } = dto

		// Validation
		const user = await this.getUser({ email })
		if (!user) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "User not found"
			})
		}
		if (user.password !== password) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Invalid password"
			})
		}

		return await this.generateTokens(user)
	}

	async refresh(refreshToken: string): Promise<{
		accessToken: string
		refreshToken: string
	}> {
		if (!refreshToken) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Token not found"
			})
		}

		const payload = await this.jwtService.decode(refreshToken)

		if (!payload) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Invalid token"
			})
		}

		try {
			await this.jwtService.verifyAsync(refreshToken, {
				secret: process.env.JWT_SECRET_KEY
			})
		} catch (error) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Token has expired"
			})
		}

		console.log("payload")
		console.log(payload)

		const user = await this.getUser({ id: payload.sub })

		return this.generateTokens(user)
	}

	async getUser(where: Prisma.UsersWhereUniqueInput): Promise<Users> {
		return this.prisma.users.findUnique({ where })
	}

	private async generateTokens(user: Users): Promise<{
		accessToken: string
		refreshToken: string
	}> {
		const accessTokenPayload = {
			name: user.name,
			surname: user.surname,
			email: user.email,
			sub: user.id,
			role: user.role
		}

		const refreshTokenPayload = {
			sub: user.id
		}

		const accessToken = await this.jwtService.signAsync(accessTokenPayload, {
			secret: process.env.JWT_SECRET_KEY,
			expiresIn: "15m"
		})
		const refreshToken = await this.jwtService.signAsync(refreshTokenPayload, {
			secret: process.env.JWT_SECRET_KEY,
			expiresIn: "90d"
		})

		return {
			accessToken,
			refreshToken
		}
	}
}
