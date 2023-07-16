import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class KeyGeneratorImpl : SecureKeyGenerator {


    override fun generate(): String {
        val keyGenerator = KeyGenerator.getInstance("AES")
        val secureRandom = SecureRandom()
        keyGenerator.init(256, secureRandom)
        val secretKey: SecretKey = keyGenerator.generateKey()
        return bytesToHex(secretKey.encoded)
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
