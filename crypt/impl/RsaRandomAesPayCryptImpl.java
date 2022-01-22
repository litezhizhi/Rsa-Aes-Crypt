package com.wjj.application.paysdk.crypt.impl;

import com.wjj.application.paysdk.crypt.PayCrypt;
import com.wjj.application.paysdk.crypt.tools.AesCryptTools;
import com.wjj.application.paysdk.crypt.tools.RsaCryptTools;
import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
/**
 * RSA+随机AES key 加密工具
 * @author hank
 * @since 2020/2/28 0028 下午 15:42
 */
public class RsaRandomAesPayCryptImpl implements PayCrypt {
    String charset = "utf-8";
    private static String split = ",";
    Integer rsaKeySize = 2048;
    Integer aesKeySize = 128;
    public RsaCryptTools.SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        // 这里可以将密钥对保存到本地
        return RsaCryptTools.generateSecretKey(rsaKeySize);
    }

    /**
     * 私钥加密
     * @param data
     * @param privateInfoStr
     * @return 使用RSA加密AES的key,使用AES加密数据
     * @throws IOException
     * @throws InvalidCipherTextException
     */
    @Override
    public String encryptData(String data, String privateInfoStr) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        // 随机生成AES key
        String aesKey = AesCryptTools.generateSecret(aesKeySize);
        // 使用AES加密数据
        String enData = AesCryptTools.encrypt(data, aesKey);
        // 使用RSA加密AES key
        String enAesKey = RsaCryptTools.encrypt(aesKey, privateInfoStr);
        return enAesKey + split + enData;
    }

    /**
     * 公钥解密
     * @param data 逗号分割:'使用RSA加密AES的key,使用AES加密数据'
     * @param publicInfoStr
     * @return 解密后的数据
     */
    @Override
    public String decryptData(String data, String publicInfoStr) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        // 拆解数据
        String[] dataArr = data.split(split);
        if(dataArr.length != 2){
            throw new IllegalArgumentException("data必须逗号分割:'使用RSA加密AES的key,使用AES加密数据'");
        }
        // 使用RSA解密AES key
        String aesKey = RsaCryptTools.decrypt(dataArr[0], publicInfoStr);
        // 使用AES解密数据
        return AesCryptTools.decrypt(dataArr[1], aesKey);
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        RsaRandomAesPayCryptImpl crypt = new RsaRandomAesPayCryptImpl();
        RsaCryptTools.SecretKey secretKey = crypt.generateSecretKey();
        System.out.println(secretKey);
        String enStr = crypt.encryptData("你好测试测试", secretKey.getPrivateKey());
        System.out.println(enStr);
        String deStr = crypt.decryptData(enStr, secretKey.getPublicKey());
        System.out.println(deStr);
        enStr = crypt.encryptData("你好测试测试hello", secretKey.getPrivateKey());
        System.out.println(enStr);
        deStr = crypt.decryptData(enStr, secretKey.getPublicKey());
        System.out.println(deStr);
    }
}
