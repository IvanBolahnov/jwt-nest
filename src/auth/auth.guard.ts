import {
	CanActivate,
	ExecutionContext,
	Injectable,
	UnauthorizedException
} from "@nestjs/common"
import { JwtService } from "@nestjs/jwt"
import { Request } from "express"

@Injectable()
export class AuthGuard implements CanActivate {
	constructor(private jwtService: JwtService) {}

	async canActivate(context: ExecutionContext): Promise<boolean> {
		const request: Request = context.switchToHttp().getRequest()

		const [type, token] = request.headers.authorization.split(" ") ?? []

		if (!type || !token) {
			throw new UnauthorizedException()
		}

		if (type !== "Bearer") {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Not Bearer token type"
			})
		}

		const payload = await this.jwtService.decode(token)

		if (!payload) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Invalid token"
			})
		}

		try {
			await this.jwtService.verifyAsync(token, {
				secret: process.env.JWT_SECRET_KEY
			})
		} catch (error) {
			throw new UnauthorizedException({
				statusCode: 401,
				message: "Token has expired"
			})
		}

		request["user"] = payload

		return true
	}
}
