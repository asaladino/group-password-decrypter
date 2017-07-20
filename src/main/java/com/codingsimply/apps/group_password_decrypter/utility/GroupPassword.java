/*
    Copyright (c) 2010, Neohapsis, Inc.
    All rights reserved.

 Implementation by Patrick Toomey

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

  - Redistributions of source code must retain the above copyright notice, this list
    of conditions and the following disclaimer.
  - Redistributions in binary form must reproduce the above copyright notice, this
    list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.
  - Neither the name of Neohapsis nor the names of its contributors may be used to
    endorse or promote products derived from this software without specific prior
    written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 Original algorithm and source code based can be found at:
 http://www.unix-ag.uni-kl.de/~massar/bin/cisco-decode
*/

package com.codingsimply.apps.group_password_decrypter.utility;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Thanks to Neohapsis for doing all the hard work.
 *
 * @author ptoomey3
 */
public class GroupPassword {

    /**
     * Pass an encrypted string to decrypt.
     *
     * @param cipherText to decrypt.
     * @return Hopefully something readable.
     */
    public static String decrypt(String cipherText) {
        byte[] cipherTextBytes;
        try {
            cipherTextBytes = DatatypeConverter.parseHexBinary(cipherText);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Encrypted Group Password");
        }
        if (cipherTextBytes.length < 48) {
            throw new IllegalArgumentException("Invalid Encrypted Group Password");
        }
        byte[] iv = new byte[8];
        System.arraycopy(cipherTextBytes, 0, iv, 0, 8);
        byte[] ht = new byte[20];
        System.arraycopy(cipherTextBytes, 0, ht, 0, 20);
        ht[19]++;
        byte[] h4 = new byte[20];
        System.arraycopy(cipherTextBytes, 20, h4, 0, 20);

        MessageDigest sha1;
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalArgumentException("Your JVM doesn't have SHA1");
        }
        byte[] h2 = sha1.digest(ht);
        ht[19] += 2;
        byte[] h3 = sha1.digest(ht);
        byte[] key = new byte[24];
        System.arraycopy(h2, 0, key, 0, 20);
        System.arraycopy(h3, 0, key, 20, 4);
        byte[] cipherTextBytesWithoutHeader = new byte[cipherTextBytes.length - 40];
        System.arraycopy(cipherTextBytes, 40, cipherTextBytesWithoutHeader, 0, cipherTextBytesWithoutHeader.length);
        ht = sha1.digest(cipherTextBytesWithoutHeader);
        if (!Arrays.equals(h4, ht)) {
            throw new IllegalArgumentException("Invalid Encrypted Group Password");
        }

        byte[] plainTextBytes;
        try {
            SecretKey secretKey = new SecretKeySpec(key, "DESede");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            plainTextBytes = decipher.doFinal(cipherTextBytesWithoutHeader);
        } catch (IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException | InvalidAlgorithmParameterException | BadPaddingException e) {
            throw new IllegalArgumentException("Invalid Encrypted Group Password");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Your JVM doesn't have 3DES");
        }
        return new String(plainTextBytes);
    }
}