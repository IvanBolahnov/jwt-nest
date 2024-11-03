import {
	Body,
	Controller,
	Get,
	Param,
	Post,
	Req,
	Res,
	UseGuards
} from "@nestjs/common"
import { AuthService } from "./auth.service"
import { Prisma, Users } from "@prisma/client"
import { Request, Response } from "express"
import { AuthGuard } from "./auth.guard"

@Controller("auth")
export class AuthController {
	constructor(private readonly authService: AuthService) {}

	@Post("registration")
	async reg(@Body() data: Prisma.UsersCreateInput): Promise<Users> {
		return await this.authService.reg(data)
	}

	@UseGuards(AuthGuard)
	@Get(":id")
	async getUser(@Param("id") id: string): Promise<Users> {
		return await this.authService.getUser({ id: Number(id) })
	}

	@Post("login")
	async login(
		@Body() data: { email: string; password: string },
		@Res({ passthrough: true }) response: Response
	): Promise<{ accessToken }> {
		const { accessToken, refreshToken } = await this.authService.login(data)

		response.cookie("refreshToken", refreshToken, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 90, // 90d
			path: "/api/auth/refresh"
		})

		return { accessToken }
	}

	@Post("refresh")
	async refresh(
		@Req() request: Request,
		@Res({ passthrough: true }) response: Response
	): Promise<{ accessToken }> {
		const token = request.cookies["refreshToken"]
		const { refreshToken, accessToken } = await this.authService.refresh(token)

		response.cookie("refreshToken", refreshToken, {
			httpOnly: true,
			maxAge: 1000 * 60 * 60 * 24 * 90, // 90d
			path: "/api/auth/refresh"
		})

		return { accessToken }
	}
}
