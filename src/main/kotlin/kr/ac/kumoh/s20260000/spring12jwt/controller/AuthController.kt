package kr.ac.kumoh.s20260000.spring12jwt.controller

import kr.ac.kumoh.s20260000.spring12jwt.model.*
import kr.ac.kumoh.s20260000.spring12jwt.service.AuthService
import kr.ac.kumoh.s20260000.spring12jwt.service.UserService
import org.slf4j.LoggerFactory
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*

@RestController
@RequestMapping("/api/v1/auth")
class AuthController(
    private val authService: AuthService,
    private val userService: UserService,
) {
    companion object {
        private val log = LoggerFactory.getLogger(AuthController::class.java)
    }

    // 회원 가입
    @PostMapping("/signup")
    fun signUp(
        @RequestBody request: SignupRequest
    ): ResponseEntity<UserResponse> {
        return ResponseEntity
            .ok(userService.signup(request).toResponse())
    }

    // 로그인
    @PostMapping("/login")
    fun login(
        @RequestBody loginRequest: LoginRequest
    ): ResponseEntity<LoginResponse> {
        return ResponseEntity
            .ok(authService.login(loginRequest))
    }

    // 토큰 갱신 (Refresh Token 필요)
    @PostMapping("/refresh")
    fun refresh(
        @RequestHeader("Authorization") authHeader: String?
    ): ResponseEntity<LoginResponse> {
        val token = extractToken(authHeader)

        return ResponseEntity
            .ok(authService.refresh(token))
    }

    // 프로필 조회 (Access Token 사용)
    @GetMapping("/profile")
    fun getProfile(
        @RequestHeader("Authorization") authHeader: String?
    ): ResponseEntity<UserResponse> {
        val token = extractToken(authHeader)

        val username = authService.verifyToken(token)

        return ResponseEntity
            .ok(userService.getProfile(username).toResponse())
    }

    private fun extractToken(authHeader: String?): String {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn(">>> [인증 실패] Authorization 헤더 형식 오류")
            throw IllegalArgumentException("인증 헤더가 누락되었거나 형식이 잘못되었습니다.")
        }
        return authHeader.substring(7)
    }
}