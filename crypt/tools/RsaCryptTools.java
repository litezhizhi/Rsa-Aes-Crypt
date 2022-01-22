package com.wjj.application.paysdk.crypt.tools;

import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 加密工具 参考:https://www.devglan.com/java8/rsa-encryption-decryption-java
 * 加密过长的会报错:
 Data must not be longer than 245 bytes
 原因是应为不同长度的密钥对应可以加密不同最大长度的原文,2048就对应245
 解决办法是:
 1.分段
 2.RSA加密是有长度限制的.单纯用RSA加密较长数据时得使用分段加密,效率低下.用RSA+AES是比较主流的做法:AES加密数据产生密文,RSA加密AES密钥产生加密后的AES密钥,然后将密文和加密后的AES密钥一起传输
 * @author hank
 * @since 2020/2/28 0028 下午 15:42
 */
public class RsaCryptTools {
    private static final String CHARSET = "utf-8";
    private static final Base64.Decoder decoder64 = Base64.getDecoder();
    private static final Base64.Encoder encoder64 = Base64.getEncoder();

    /**
     * 生成公私钥
     * @param keySize key大小 推荐2048
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecretKey generateSecretKey(int keySize) throws NoSuchAlgorithmException {
        //生成密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize, new SecureRandom());
        KeyPair pair = keyGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        //这里可以将密钥对保存到本地
        return new SecretKey(encoder64.encodeToString(publicKey.getEncoded()), encoder64.encodeToString(privateKey.getEncoded()));
    }
    /**
     * 私钥加密
     * @param data
     * @param privateInfoStr
     * @return
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    public static String encrypt(String data, String privateInfoStr) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, getPrivateKey(privateInfoStr));
        return encoder64.encodeToString(cipher.doFinal(data.getBytes(CHARSET)));
    }

    /**
     * 公钥解密
     * @param data
     * @param publicInfoStr
     * @return
     */
    public static String decrypt(String data, String publicInfoStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] encryptDataBytes=decoder64.decode(data.getBytes(CHARSET));
        //解密
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, getPublicKey(publicInfoStr));
        return new String(cipher.doFinal(encryptDataBytes), CHARSET);
    }
    private static PublicKey getPublicKey(String base64PublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(base64PublicKey.getBytes()));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    private static PrivateKey getPrivateKey(String base64PrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64PrivateKey.getBytes()));
        KeyFactory keyFactory = null;
        keyFactory = KeyFactory.getInstance("RSA");
        privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 密钥实体
     * @author hank
     * @since 2020/2/28 0028 下午 16:27
     */
    public static class SecretKey {
        /**
         * 公钥
         */
        private String publicKey;
        /**
         * 私钥
         */
        private String privateKey;

        public SecretKey(String publicKey, String privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        @Override
        public String toString() {
            return "SecretKey{" +
                    "publicKey='" + publicKey + '\'' +
                    ", privateKey='" + privateKey + '\'' +
                    '}';
        }
    }

    private static void writeToFile(String path, byte[] key) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();

        try(FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(key);
            fos.flush();
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        SecretKey secretKey = generateSecretKey(2048);
        System.out.println(secretKey);
        String enStr = encrypt("你好测试测试", secretKey.getPrivateKey());
        System.out.println(enStr);
        String deStr = decrypt(enStr, secretKey.getPublicKey());
        System.out.println(deStr);
        enStr = encrypt("你好测试测试hello", secretKey.getPrivateKey());
        System.out.println(enStr);
        deStr = decrypt(enStr, secretKey.getPublicKey());
        System.out.println(deStr);
    }

}
