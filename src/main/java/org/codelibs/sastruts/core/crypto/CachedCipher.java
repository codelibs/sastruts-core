/*
 * Copyright 2012 the CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.sastruts.core.crypto;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.codelibs.sastruts.core.exception.BadPaddingRuntimeException;
import org.codelibs.sastruts.core.exception.IllegalBlockSizeRuntimeException;
import org.codelibs.sastruts.core.exception.InvalidKeyRuntimeException;
import org.codelibs.sastruts.core.exception.NoSuchAlgorithmRuntimeException;
import org.codelibs.sastruts.core.exception.NoSuchPaddingRuntimeException;
import org.codelibs.sastruts.core.exception.UnsupportedEncodingRuntimeException;
import org.seasar.framework.container.annotation.tiger.Binding;
import org.seasar.framework.container.annotation.tiger.BindingType;
import org.seasar.framework.util.Base64Util;

public class CachedCipher {
    protected static final String UTF_8 = "UTF-8";

    public String algorithm = "Blowfish";

    @Binding(bindingType = BindingType.MUST)
    public String key;

    public String charsetName = UTF_8;

    protected Queue<Cipher> encryptoQueue = new ConcurrentLinkedQueue<Cipher>();

    protected Queue<Cipher> decryptoQueue = new ConcurrentLinkedQueue<Cipher>();

    public byte[] encrypto(final byte[] data) {
        final Cipher cipher = pollEncryptoCipher();
        byte[] encrypted;
        try {
            encrypted = cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalBlockSizeRuntimeException(e);
        } catch (BadPaddingException e) {
            throw new BadPaddingRuntimeException(e);
        } finally {
            offerEncryptoCipher(cipher);
        }
        return encrypted;
    }

    public String encryptoText(final String text) {
        try {
            return Base64Util.encode(encrypto(text.getBytes(charsetName)));
        } catch (final UnsupportedEncodingException e) {
            throw new UnsupportedEncodingRuntimeException(e);
        }
    }

    public byte[] decrypto(final byte[] data) {
        final Cipher cipher = pollDecryptoCipher();
        byte[] decrypted;
        try {
            decrypted = cipher.doFinal(data);
        } catch (IllegalBlockSizeException e) {
            throw new IllegalBlockSizeRuntimeException(e);
        } catch (BadPaddingException e) {
            throw new BadPaddingRuntimeException(e);
        } finally {
            offerDecryptoCipher(cipher);
        }
        return decrypted;
    }

    public String decryptoText(final String text) {
        try {
            return new String(decrypto(Base64Util.decode(text)), charsetName);
        } catch (final UnsupportedEncodingException e) {
            throw new UnsupportedEncodingRuntimeException(e);
        }
    }

    protected Cipher pollEncryptoCipher() {
        Cipher cipher = encryptoQueue.poll();
        if (cipher == null) {
            final SecretKeySpec sksSpec =
                new SecretKeySpec(key.getBytes(), algorithm);
            try {
                cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.ENCRYPT_MODE, sksSpec);
            } catch (InvalidKeyException e) {
                throw new InvalidKeyRuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new NoSuchAlgorithmRuntimeException(e);
            } catch (NoSuchPaddingException e) {
                throw new NoSuchPaddingRuntimeException(e);
            }
        }
        return cipher;
    }

    protected void offerEncryptoCipher(final Cipher cipher) {
        encryptoQueue.offer(cipher);
    }

    protected Cipher pollDecryptoCipher() {
        Cipher cipher = decryptoQueue.poll();
        if (cipher == null) {
            final SecretKeySpec sksSpec =
                new SecretKeySpec(key.getBytes(), algorithm);
            try {
                cipher = Cipher.getInstance(algorithm);
                cipher.init(Cipher.DECRYPT_MODE, sksSpec);
            } catch (InvalidKeyException e) {
                throw new InvalidKeyRuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new NoSuchAlgorithmRuntimeException(e);
            } catch (NoSuchPaddingException e) {
                throw new NoSuchPaddingRuntimeException(e);
            }
        }
        return cipher;
    }

    protected void offerDecryptoCipher(final Cipher cipher) {
        decryptoQueue.offer(cipher);
    }
}
