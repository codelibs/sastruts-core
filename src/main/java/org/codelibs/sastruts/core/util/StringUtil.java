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
package org.codelibs.sastruts.core.util;

import java.io.UnsupportedEncodingException;

import org.codelibs.sastruts.core.exception.UnsupportedEncodingRuntimeException;

/**
 * Extended StringUtil.
 * 
 * @author shinsuke
 * 
 */
public class StringUtil extends org.seasar.framework.util.StringUtil {
    /**
     * A empty string
     */
    public static final String EMPTY_STRING = "";

    /**
     */
    protected StringUtil() {
    }

    public static String newString(byte[] bytes, String charsetName) {
        try {
            return new String(bytes, charsetName);
        } catch (UnsupportedEncodingException e) {
            throw new UnsupportedEncodingRuntimeException(e);
        }
    }
}