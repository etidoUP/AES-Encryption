package com.etido.crypto.Basic;

import android.util.*;
import java.io.*;
import java.security.*;
import java.text.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCrypto {

  public static final String PROVIDER = "BC";
  public static final int SALT_LENGTH = 20;
  public static final int IV_LENGTH = 16;
  public static final int PBE_ITERATION_COUNT = 1000;
  private static final String RANDOM_ALGORITHM = "SHA1PRNG";
  //  private static final String HASH_ALGORITHM = "SHA-512";
  private static final String PBE_ALGORITHM = "PBEWithSHA256And256BitAES-CBC-BC";
  private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
  public static final String SECRET_KEY_ALGORITHM = "AES";
  // private static final String TAG = "EncryptionPassword";
  public static String mCipher = "";
  public static String encryptedPassword = "";
  public static String getSaltKey = "";
  public static String Decipher = "";
  public static String mTAG = AESCrypto.class.getName();

  public static String encrypt(SecretKey secret, String cleartext) throws Exception {
    try {
      byte[] iv = generateIv();
      String ivHex = byteArrayToHexString(iv);
      IvParameterSpec ivspec = new IvParameterSpec(iv);
      Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
      encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
      byte[] encryptedText = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
      String encryptedHex = byteArrayToHexString(encryptedText);
      return ivHex + encryptedHex;
    } catch (Exception e) {
      Log.e("SecurityException", e.getCause().getLocalizedMessage());
      throw new Exception("Unable to encrypt", e);
    }
  }

  public static String decrypt(SecretKey secret, String encrypted) throws Exception {
    try {
      Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
      String ivHex = encrypted.substring(0, IV_LENGTH * 2);
      String encryptedHex = encrypted.substring(IV_LENGTH * 2);
      IvParameterSpec ivspec = new IvParameterSpec(hexStringToByteArray(ivHex));
      decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
      byte[] decryptedText = decryptionCipher.doFinal(hexStringToByteArray(encryptedHex));
      String decrypted = new String(decryptedText, "UTF-8");
      return decrypted;
    } catch (Exception e) {
      Log.e("SecurityException", e.getCause().getLocalizedMessage());
      throw new Exception("Unable to decrypt", e);
    }
  }

  public static String generateSalt() throws Exception {
    try {
      SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
      byte[] salt = new byte[SALT_LENGTH];
      random.nextBytes(salt);
      String saltHex = byteArrayToHexString(salt);
      return saltHex;
    } catch (Exception e) {
      throw new Exception("Unable to generate salt", e);
    }
  }

  public static String byteArrayToHexString(byte[] b) {
    StringBuffer sb = new StringBuffer(b.length * 2);
    for (int i = 0; i < b.length; i++) {
      int v = b[i] & 0xff;
      if (v < 16) {
        sb.append('0');
      }
      sb.append(Integer.toHexString(v));
    }
    return sb.toString().toUpperCase();
  }

  public static byte[] hexStringToByteArray(String s) {
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < b.length; i++) {
      int index = i * 2;
      int v = Integer.parseInt(s.substring(index, index + 2), 16);
      b[i] = (byte) v;
    }
    return b;
  }

  public static SecretKey getSecretKey(String password, String salt) throws Exception {
    try {
      PBEKeySpec pbeKeySpec =
          new PBEKeySpec(
              password.toCharArray(), hexStringToByteArray(salt), PBE_ITERATION_COUNT, 256);
      SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM, PROVIDER);
      SecretKey tmp = factory.generateSecret(pbeKeySpec);
      SecretKey secret = new SecretKeySpec(tmp.getEncoded(), SECRET_KEY_ALGORITHM);
      return secret;
    } catch (Exception e) {
      throw new Exception("Unable to get secret key", e);
    }
  }

  private static byte[] generateIv() throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
    byte[] iv = new byte[IV_LENGTH];
    random.nextBytes(iv);
    return iv;
  }

  // TODO: Implement this method to encode text

  public static String EncodeText(String _mValue) {
    if (_mValue != null && !_mValue.isEmpty()) {
      SecretKey secretKey = null;
      try {
        secretKey = getSecretKey(_mValue, generateSalt());
        byte[] encoded = secretKey.getEncoded();
        getSaltKey = byteArrayToHexString(encoded);
        // parse salt to string
        encryptedPassword = encrypt(secretKey, _mValue);
        mCipher = encryptedPassword;
      } catch (Exception e) {
        Log.e(mTAG, e.getMessage());
      }
    }
    return encryptedPassword;
  }

  // TODO: Implement this method to Decode the cipher text

  public static String DecodeText(String _mCipher) {
    if (_mCipher != null && !_mCipher.isEmpty()) {
      try {
        byte[] _encoded = hexStringToByteArray(getSaltKey);
        SecretKey aesKey = new SecretKeySpec(_encoded, SECRET_KEY_ALGORITHM);
        Decipher = decrypt(aesKey, _mCipher);
      } catch (Exception e) {
        Log.e(mTAG, e.getMessage());
      }
    }
    return Decipher;
  }
}
