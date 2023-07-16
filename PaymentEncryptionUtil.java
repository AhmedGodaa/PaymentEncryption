import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class PaymentEncryptionUtil {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int ITERATION_COUNT = 65536;
    private static final int KEY_LENGTH = 256;
    private static final String SECRET_KEY = "mysecretkey12345";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public static String encrypt(String data) throws Exception {
        byte[] salt = new byte[16];
        SECURE_RANDOM.nextBytes(salt);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        byte[] iv = new byte[IV_LENGTH_BYTE];
        SECURE_RANDOM.nextBytes(iv);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        byte[] encryptedData = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(4 + salt.length + iv.length + encryptedData.length);
        byteBuffer.putInt(salt.length);
        byteBuffer.put(salt);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public static String decrypt(String encryptedData) throws Exception {
        ByteBuffer byteBuffer = ByteBuffer.wrap(Base64.getDecoder().decode(encryptedData));

        int saltLength = byteBuffer.getInt();
        byte[] salt = new byte[saltLength];
        byteBuffer.get(salt);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        byteBuffer.get(iv);

        byte[] encrypted = new byte[byteBuffer.remaining()];
        byteBuffer.get(encrypted);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(SECRET_KEY.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);
        SecretKey secretKey = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH_BIT, iv);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        byte[] decryptedData = cipher.doFinal(encrypted);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}
