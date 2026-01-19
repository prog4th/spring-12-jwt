package kr.ac.kumoh.s20260000.spring12jwt.exception

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.MalformedJwtException
import io.jsonwebtoken.security.SignatureException
import org.slf4j.LoggerFactory
import org.slf4j.MDC
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.time.LocalDateTime

// 공통 에러 응답을 위한 DTO (Data Transfer Object)
data class ErrorResponse(
    val message: String,
    val code: String,
    val traceId: String? = null,
    val timestamp: LocalDateTime = LocalDateTime.now(),
)

@RestControllerAdvice
class GlobalExceptionHandler {
    companion object {
        private val log = LoggerFactory.getLogger(GlobalExceptionHandler::class.java)
    }

    /**
     * Verification 실패: Token의 Signature가 일치하지 않음
     */
    @ExceptionHandler(SignatureException::class, MalformedJwtException::class)
    fun handleJwtSignatureException(e: Exception): ResponseEntity<ErrorResponse> {
        log.error("위조된 토큰 감지: {}", e.message)

        val errorBody = ErrorResponse(
            message = "유효하지 않은 토큰입니다. 서명을 확인하세요.",
            code = "INVALID_TOKEN_SIGNATURE",
            traceId = MDC.get("traceId")
        )
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(errorBody)
    }

    /**
     * Validation 실패: Token의 유효 기간(exp)이 만료됨
     */
    @ExceptionHandler(ExpiredJwtException::class)
    fun handleExpiredJwtException(e: ExpiredJwtException): ResponseEntity<ErrorResponse> {
        log.warn("만료된 토큰 사용 시도: {}", e.claims.subject)

        val errorBody = ErrorResponse(
            message = "토큰이 만료되었습니다. 다시 로그인하거나 갱신하세요.",
            code = "EXPIRED_TOKEN",
            traceId = MDC.get("traceId")
        )
        return ResponseEntity
            .status(HttpStatus.UNAUTHORIZED)
            .body(errorBody)
    }

    @ExceptionHandler(IllegalArgumentException::class)
    fun handleIllegalArgumentException(
        e: IllegalArgumentException
    ): ResponseEntity<ErrorResponse> {
        log.warn("잘못된 요청 발생: {}", e.message)

        val errorBody = ErrorResponse(
            message = e.message ?: "잘못된 요청입니다.",
            code = "BAD_REQUEST_001",
            traceId = MDC.get("traceId")
        )
        return ResponseEntity
            .badRequest()
            .body(errorBody)
    }

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidationException(
        e: MethodArgumentNotValidException
    ): ResponseEntity<ErrorResponse> {
        val errorMessage = e.bindingResult.fieldErrors
            .joinToString(" ") {
                it.defaultMessage ?: "검증 오류"
            }

        log.warn("검증 오류 발생: {}", errorMessage)

        val errorBody = ErrorResponse(
            message = errorMessage,
            code = "VALIDATION_ERROR",
            traceId = MDC.get("traceId")
        )

        return ResponseEntity
            .badRequest()
            .body(errorBody)
    }
}