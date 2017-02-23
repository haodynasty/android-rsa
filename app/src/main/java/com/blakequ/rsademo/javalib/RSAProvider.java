package com.blakequ.rsademo.javalib;

import com.blakequ.rsa.ArrayUtils;
import com.blakequ.rsa.Base64Utils;
import com.blakequ.rsa.FileUtils;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * Copyright (C) BlakeQu All Rights Reserved <blakequ@gmail.com>
 * <p>
 * Licensed under the blakequ.com License, Version 1.0 (the "License");
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * <p>
 * author  : quhao <blakequ@gmail.com> <br>
 * date     : 2017/2/22 16:03 <br>
 * last modify author : <br>
 * version : 1.0 <br>
 * description:
 */

public class RSAProvider {

    /**
     * KEY_ALGORITHM
     */
    public static final String KEY_ALGORITHM = "RSA";
    /**
     * 加密Key的长度等于1024
     */
    public static int KEYSIZE = 1024;
    /**
     * 解密时必须按照此分组解密
     */
    public static int decodeLen = KEYSIZE / 8;
    /**
     * 加密时小于117即可
     */
    public static int encodeLen = 110;//(DEFAULT_KEY_SIZE / 8) - 11;
    /**
     * 公钥
     */
    private static final String PUBLIC_KEY = "publicKey";
    /**
     * 私钥
     */
    private static final String PRIVATE_KEY = "privateKey";
    /**
     * MODULES
     */
    private static final String MODULES = "RSAModules";
    /**
     * 签名算法
     */
    public static final String SIGNATURE_ALGORITHM = "MD5withRSA";
    /**
     * 加密填充方式,android系统的RSA实现是"RSA/None/NoPadding"，而标准JDK实现是"RSA/None/PKCS1Padding" ，这造成了在android机上加密后无法在服务器上解密的原因
     */
    public static final String ECB_PKCS1_PADDING = "RSA/ECB/PKCS1Padding";

    /**
     *
     * 生成KeyPair
     * @return
     * @throws Exception
     */
    public static Map<String, Object> generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(KEYSIZE);
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // 公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        // 私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        BigInteger modules = privateKey.getModulus();

        Map<String, Object> keys = new HashMap<String, Object>(3);
        keys.put(PUBLIC_KEY, publicKey);
        keys.put(PRIVATE_KEY, privateKey);
        keys.put(MODULES, modules);
        return keys;
    }

    public static byte[] getModulesBytes(Map<String, Object> keys) {
        BigInteger big = (BigInteger) keys.get(MODULES);
        return big.toByteArray();
    }

    /**
     *
     * 取得私钥
     * @return
     * @throws Exception
     */
    public static String getPrivateKeyBytes(Map<String, Object> keys) throws Exception {
        Key key = (Key) keys.get(PRIVATE_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    /**
     * 取得公钥
     *
     * @return
     * @throws Exception
     */
    public static String getPublicKeyBytes(Map<String, Object> keys) throws Exception {
        Key key = (Key) keys.get(PUBLIC_KEY);
        return Base64Utils.encode(key.getEncoded());
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data 已加密数据
     * @param privateKey 私钥(BASE64编码)
     *
     * @return
     * @throws Exception
     */
    public static String sign(byte[] data, String privateKey) throws Exception {
        PrivateKey privateK = loadPrivateKey(privateKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateK);
        signature.update(data);
        return Base64Utils.encode(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign 数字签名
     *
     * @return
     * @throws Exception
     *
     */
    public static boolean verify(byte[] data, String publicKey, String sign)
            throws Exception {
        PublicKey publicK = loadPublicKey(publicKey);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64Utils.decode(sign));
    }

    /**
     *
     * 通过私钥加密
     * @param encryptedData
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptPrivateKey(byte[] encryptedData, String key) throws Exception {
        if (encryptedData == null){
            throw  new IllegalArgumentException("Input encryption data is null");
        }
        byte[] encode = new byte[] {};
        for (int i = 0; i < encryptedData.length; i += encodeLen) {
            byte[] subarray = com.blakequ.rsa.ArrayUtils.subarray(encryptedData, i, i + encodeLen);
            byte[] doFinal = encryptByPrivateKey(subarray, key);
            encode = com.blakequ.rsa.ArrayUtils.addAll(encode, doFinal);
        }
        return encode;
    }

    /**
     * 通过公钥解密
     * @param encode
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptPublicKey(byte[] encode, String key) throws Exception {
        if (encode == null){
            throw  new IllegalArgumentException("Input encryption data is null");
        }
        byte [] buffers = new byte[]{};
        for (int i = 0; i < encode.length; i += decodeLen) {
            byte[] subarray = com.blakequ.rsa.ArrayUtils.subarray(encode, i, i + decodeLen);
            byte[] doFinal = decryptByPublicKey(subarray, key);
            buffers = com.blakequ.rsa.ArrayUtils.addAll(buffers, doFinal);
        }
        return buffers;
    }

    /**
     *
     * 通过公钥加密
     * @param encryptedData
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptPublicKey(byte[] encryptedData, String key) throws Exception {
        if (encryptedData == null){
            throw  new IllegalArgumentException("Input encryption data is null");
        }
        byte[] encode = new byte[] {};
        for (int i = 0; i < encryptedData.length; i += encodeLen) {
            byte[] subarray = com.blakequ.rsa.ArrayUtils.subarray(encryptedData, i, i + encodeLen);
            byte[] doFinal = encryptByPublicKey(subarray, key);
            encode = com.blakequ.rsa.ArrayUtils.addAll(encode, doFinal);
        }
        return encode;
    }

    /**
     * 通过私钥解密
     * @param encode
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptPrivateKey(byte[] encode, String key) throws Exception {
        if (encode == null){
            throw  new IllegalArgumentException("Input data is null");
        }
        byte [] buffers = new byte[]{};
        for (int i = 0; i < encode.length; i += decodeLen) {
            byte[] subarray = com.blakequ.rsa.ArrayUtils.subarray(encode, i, i + decodeLen);
            byte[] doFinal = decryptByPrivateKey(subarray, key);
            buffers = ArrayUtils.addAll(buffers, doFinal);
        }
        return buffers;
    }

    /**
     * 从字符串中加载公钥
     *
     * @param publicKeyStr 公钥数据字符串
     * @throws Exception 加载公钥时产生的异常
     */
    public static PublicKey loadPublicKey(String publicKeyStr) throws Exception {
        try {
            byte[] buffer = Base64Utils.decode(publicKeyStr);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            //表示根据 ASN.1 类型 SubjectPublicKeyInfo 进行编码的公用密钥的 ASN.1 编码。
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 从字符串中加载私钥<br>
     * 加载时使用的是PKCS8EncodedKeySpec（PKCS#8编码的Key指令）。
     *
     * @param privateKeyStr
     * @return
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(String privateKeyStr) throws Exception {
        try {
            byte[] buffer = Base64Utils.decode(privateKeyStr);
            //表示按照 ASN.1 类型 PrivateKeyInfo 进行编码的专用密钥的 ASN.1 编码。
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 从文件中输入流中加载公钥
     *
     * @param in 公钥输入流
     * @throws Exception 加载公钥时产生的异常
     */
    public static PublicKey loadPublicKey(InputStream in) throws Exception {
        try {
            return loadPublicKey(FileUtils.readString(in));
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }

    /**
     * 读取私钥
     *
     * @param in
     * @return
     * @throws Exception
     */
    public static PrivateKey loadPrivateKey(InputStream in) throws Exception {
        try {
            return loadPrivateKey(FileUtils.readString(in));
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    /**
     * 用私钥解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        if (data == null){
            throw  new IllegalArgumentException("Input data is null");
        }
        //取得私钥
        Key privateKey = loadPrivateKey(key);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     *
     * 用公钥解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] decryptByPublicKey(byte[] data, String key) throws Exception {
        if (data == null){
            throw  new IllegalArgumentException("Input data is null");
        }
        //取得公钥
        Key publicKey = loadPublicKey(key);
        // 对数据解密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);//publicKey.getAlgorithm()
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     *
     * 用公钥加密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        if (data == null){
            throw  new IllegalArgumentException("Input data is null");
        }
        // 取得公钥
        Key publicKey = loadPublicKey(key);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 用私钥加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    private static byte[] encryptByPrivateKey(byte[] data, String key) throws Exception {
        if (data == null){
            throw  new IllegalArgumentException("Input data is null");
        }
        // 取得私钥
        Key privateKey = loadPrivateKey(key);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(ECB_PKCS1_PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

}
