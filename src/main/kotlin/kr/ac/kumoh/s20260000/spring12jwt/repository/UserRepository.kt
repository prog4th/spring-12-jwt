package kr.ac.kumoh.s20260000.spring12jwt.repository

import kr.ac.kumoh.s20260000.spring12jwt.model.User
import org.springframework.data.mongodb.repository.MongoRepository

interface UserRepository : MongoRepository<User, String> {
    fun existsByUsername(username: String): Boolean
    fun findByUsername(username: String): User?
}