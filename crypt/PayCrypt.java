package com.wjj.application.paysdk.crypt;

import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.IOException;

/**
 * 支付加密工具
 * @author hank
 * @since 2020/2/28 0028 下午 15:42
 */
public interface PayCrypt {
    /**
     * 私钥加密
     * @param data
     * @param privateInfoStr
     * @return
     * @throws Exception
     */
    String encryptData(String data, String privateInfoStr) throws Exception;

    /**
     * 公钥解密
     * @param data
     * @param publicInfoStr
     * @return
     * @throws Exception
     */
    String decryptData(String data, String publicInfoStr) throws Exception;
}
