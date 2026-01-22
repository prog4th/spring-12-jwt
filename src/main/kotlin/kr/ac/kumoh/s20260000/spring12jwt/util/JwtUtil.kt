package kr.ac.kumoh.s20260000.spring12jwt.util

import io.jsonwebtoken.ExpiredJwtException
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.util.*
import javax.crypto.SecretKey

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

//    private lateinit var key: SecretKey
//
//    @PostConstruct
//    fun init() {
//        // base64EncodedSecretKey가 주입된 후, key 초기화
//        // getDecoder() 대신 getUrlDecoder() 사용
//        val decodedKey = Base64.getUrlDecoder().decode(base64EncodedSecretKey)
//        key = Keys.hmacShaKeyFor(decodedKey)
//    }

    private val key: SecretKey by lazy  {
        val decodedKey = Base64.getUrlDecoder().decode(base64EncodedSecretKey)
        Keys.hmacShaKeyFor(decodedKey)
    }

    fun generateAccessToken(username: String): String {
        return Jwts.builder()
            .subject(username)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + ACCESS_TOKEN_EXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun generateRefreshToken(username: String): String {
        return Jwts.builder()
            .subject(username)
            .issuedAt(Date())
            .expiration(Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME))
            .signWith(key)
            .compact()
    }

    fun validateToken(token: String): Boolean {
        return try {
            Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
            true
        } catch (e: SecurityException) {
            // Verification 실패 (서명 위조 등)
            false
        } catch (e: ExpiredJwtException) {
            // Validation 실패 (만료된 토큰)
            //println("!!!!!!!!!! JWT expired")
            false
        } catch (e: Exception) {
            false
        }
    }

    fun extractUsername(token: String): String {
        return Jwts.parser()
            .verifyWith(key)
            .build()
            .parseSignedClaims(token)
            .payload.subject
    }
}