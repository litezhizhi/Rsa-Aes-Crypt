package com.wjj.application.paysdk.crypt.tools;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES工具类
 * 参考: https://howtodoinjava.com/security/java-aes-encryption-example/
 * @author hank
 * @since 2020/3/3 0003 下午 18:00
 */
public class AesCryptTools {
    private static final String CHARSET = "utf-8";

    /**
     * 生成随机密钥
     * @param keySize 密钥大小推荐128 256
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateSecret(int keySize) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(keySize, new SecureRandom());
        SecretKey key = generator.generateKey();
       return byteToHexString(key.getEncoded());
    }

    public static String encrypt(String strToEncrypt, String secret) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretKey = getKey(secret);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
    }

    public static String decrypt(String strToDecrypt, String secret) throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            SecretKeySpec secretKey = getKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
    }
    private static SecretKeySpec getKey(String myKey) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        byte[] key = myKey.getBytes(CHARSET);
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        return new SecretKeySpec(key, "AES");
    }
    /**
     * byte数组转化为16进制字符串
     * @param bytes
     * @return
     */
    private static String byteToHexString(byte[] bytes){
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex=Integer.toHexString(bytes[i]);
            if(strHex.length() > 3){
                sb.append(strHex.substring(6));
            } else {
                if(strHex.length() < 2){
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return  sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, UnsupportedEncodingException {
        String key = generateSecret(256);
        String enData = encrypt("你好测试hello", key);
        System.out.println(enData);
        String deData = decrypt(enData, key);
        System.out.println(deData);
        enData = encrypt("你好测试", key);
        System.out.println(enData);
        deData = decrypt(enData, key);
        System.out.println(deData);
    }
}
