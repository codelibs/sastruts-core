/*
 * Copyright 2004-2010 the Seasar Foundation and the Others.
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
package org.codelibs.sastruts.core.exception;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * {@link NoSuchAlgorithmException}をラップする例外です。
 * 
 * @author shinsuke
 */
public class InvalidKeyRuntimeException extends SSCRuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * {@link InvalidKeyRuntimeException}を作成します。
     * 
     * @param cause
     *            原因となった例外
     */
    public InvalidKeyRuntimeException(final InvalidKeyException cause) {
        super("ESSC0001", new Object[] { cause.getClass().getName() }, cause);
    }

}