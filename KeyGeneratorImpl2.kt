import java.time.Duration
import java.time.Instant

class KeyGeneratorImpl : SecureKeyGenerator {

    private val keyExpirationTime: Duration = Duration.ofMinutes(30)
    private var keyExpirationInstant: Instant = Instant.now().plus(keyExpirationTime)

    private var currentKey: SecretKey? = null

    override fun generate(): String {
        val now = Instant.now()
        if (now.isAfter(keyExpirationInstant)) {
            val keyGenerator = KeyGenerator.getInstance("AES")
            val secureRandom = SecureRandom()
            keyGenerator.init(256, secureRandom)
            val secretKey: SecretKey = keyGenerator.generateKey()
            currentKey = secretKey
            keyExpirationInstant = now.plus(keyExpirationTime)
        }
        return bytesToHex(currentKey!!.encoded)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val chars = "0123456789ABCDEF".toCharArray()
        val hexChars = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            hexChars[i * 2] = chars[v ushr 4]
            hexChars[i * 2 + 1] = chars[v and 0x0F]
        }
        return String(hexChars)
    }

}
