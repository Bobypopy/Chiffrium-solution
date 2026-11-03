import java.security.MessageDigest

fun tokenHash(value: String): ByteArray = MessageDigest.getInstance("SHA-1").digest(value.toByteArray())

fun strongHash(value: String): ByteArray = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
