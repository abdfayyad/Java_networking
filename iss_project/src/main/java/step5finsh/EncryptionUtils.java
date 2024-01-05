package step5finsh;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.util.Base64;

public class EncryptionUtils {
    private static final String ENCRYPTION_ALGORITHM = "DES";
    /**
     * Encrypt data using a secret key.
     *
     * @param secretKey SecretKey instance
     * @param data      Data to be encrypted
     * @return Encrypted data as a Base64 encoded string
     * @throws Exception If encryption fails
     */
    public static String encrypt(SecretKey secretKey, String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * Decrypt data using a secret key.
     *
     * @param secretKey SecretKey instance
     * @param encryptedData Base64 encoded encrypted data
     * @return Decrypted data as a string
     * @throws Exception If decryption fails
     */
    public static String decrypt(SecretKey secretKey, String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes);
    }

    /**
     * Generate a SecretKey using DES algorithm.
     *
     * @param keyStr Key string for generating SecretKey
     * @return SecretKey instance
     * @throws Exception If key generation fails
     */
     public static SecretKey generateSecretKey(String keyStr) throws Exception {
        DESKeySpec desKeySpec = new DESKeySpec(keyStr.getBytes());
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ENCRYPTION_ALGORITHM);
        return keyFactory.generateSecret(desKeySpec);
    }
}