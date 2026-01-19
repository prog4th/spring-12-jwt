package kr.ac.kumoh.s20260000.spring12jwt.util

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import jakarta.annotation.PostConstruct
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.security.Key
import java.util.*

@Component
class JwtUtil {
    companion object {
        //const val ACCESS_TOKEN_EXPIRATION_TIME = 60L * 60 * 1000 // 1 시간
        const val ACCESS_TOKEN_EXPIRATION_TIME = 20L * 1000 // 20 초

        //const val REFRESH_TOKEN_EXPIRATION_TIME = 15L * 24 * 60 * 60 * 1000 // 15일
        const val REFRESH_TOKEN_EXPIRATION_TIME = 40L * 1000 // 40 초
    }

    @Value("\${jwt.secret}")
    private lateinit var base64EncodedSecretKey: String

    private lateinit var key: Key

    @PostConstruct
    fun init() {
        // base64EncodedSecretKey가 주입된 후, key 초기화
        val decodedKey = Base64.getUrlDecoder().decode(base64EncodedSecretKey)
        key = Keys.hmacShaKeyFor(decodedKey)
    }

    fun generateAccessToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()
    }

    fun generateRefreshToken(username: String): String {
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date())
            .setExpiration(Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
            .signWith(key, SignatureAlgorithm.HS256)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            // Verification (진위 확인)
            val claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .body

            // Validation (유효성 검증)
            claims.expiration.after(Date())
        } catch (e: SecurityException) {
            // Verification 실패 (서명 위조 등)
            false
        } catch (e: ExpiredJwtException) {
            // Validation 실패 (만료된 토큰)
            false
        } catch (e: Exception) {
            false
        }
    }

    fun extractUsername(token: String): String {
        return Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(token)
            .body.subject
    }
}