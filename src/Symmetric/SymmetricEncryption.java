package Symmetric;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class SymmetricEncryption {
    private SecretKey secretKey;
    private String algorithm;
    private String key;
    private int keySize;
    private String charset;

    public SymmetricEncryption(String algorithm, int keySize, String key, String charset) throws Exception {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.key = key;
        this.charset = charset;
        generateKey();
    }

    private void generateKey() throws Exception {
        if (key != null && !key.isEmpty()) {
            byte[] keyBytes = key.getBytes(charset);
            if (keyBytes.length != 8 && !algorithm.equals("AES")) {
                throw new IllegalArgumentException("Key must be 8 bytes for DES or 16/32 bytes for AES.");
            }
            this.secretKey = new SecretKeySpec(keyBytes, algorithm);
        } else {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm);
            keyGenerator.init(keySize);
            this.secretKey = keyGenerator.generateKey();
        }
    }

    public String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(charset));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decryptedBytes, charset);
    }

    public String getSecretKey() {
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

    public static void main(String[] args) {
        try {
            String base64Key = "12345612";  // 8 bytes key for DES
            SymmetricEncryption desEncryption = new SymmetricEncryption("DES", 56, base64Key, "UTF-8");

            String originalText = "Hello, World!";
            String encryptedText = desEncryption.encrypt(originalText);
            String decryptedText = desEncryption.decrypt(encryptedText);

            System.out.println("Original: " + originalText);
            System.out.println("Encrypted: " + encryptedText);
            System.out.println("Decrypted: " + decryptedText);
            System.out.println("Secret Key: " + desEncryption.getSecretKey());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
