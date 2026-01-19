package kr.ac.kumoh.s20260000.spring12jwt.service

import kr.ac.kumoh.s20260000.spring12jwt.model.LoginRequest
import kr.ac.kumoh.s20260000.spring12jwt.model.LoginResponse
import kr.ac.kumoh.s20260000.spring12jwt.util.JwtUtil
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service

@Service
class AuthService(
    private val userService: UserService,
    private val jwt: JwtUtil,
) {
    companion object {
        private val log = LoggerFactory.getLogger(AuthService::class.java)
    }

    fun login(request: LoginRequest): LoginResponse {
        // 1. 사용자 검증
        val user = userService.validateUser(request.username, request.password)

        // 2. 토큰 생성
        val accessToken = jwt.generateAccessToken(user.username)
        val refreshToken = jwt.generateRefreshToken(user.username)

        return LoginResponse(
            accessToken = accessToken,
            refreshToken = refreshToken,
            username = user.username,
            role = user.role,
            nickname = user.nickname
        )
    }

    fun refresh(token: String): LoginResponse {
        log.info(">>> [토큰 갱신 시도] Token: {}", token)

        // 1. 토큰 유효성 검증
        if (!jwt.validateToken(token)) {
            log.warn(">>> [토큰 갱신 실패] 만료되거나 유효하지 않은 Refresh Token")
            throw IllegalArgumentException("Refresh 토큰이 만료되었습니다. 다시 로그인하세요.")
        }

        // 2. 토큰에서 정보 추출 및 사용자 확인
        val username = jwt.extractUsername(token)
        val user = userService.getProfile(username)

        log.info(">>> [토큰 갱신 성공] Username: {}", username)

        // 3. 새로운 토큰 생성
        return LoginResponse(
            accessToken = jwt.generateAccessToken(user.username),
            refreshToken = jwt.generateRefreshToken(user.username),
            username = user.username,
            role = user.role,
            nickname = user.nickname
        )
    }

    fun verifyToken(token: String): String {
        log.info(">>> [토큰 유효성 검증] token: {}", token)

        if (!jwt.validateToken(token)) {
            log.warn(">>> [토큰 유효성 검증 실패] 유효하지 않거나 만료된 토큰")
            throw IllegalArgumentException("유효하지 않거나 만료된 토큰입니다.")
        }

        val username = jwt.extractUsername(token)
        log.info(">>> [토큰 유효성 검증 성공] Username: {}", username)

        return username
    }
}