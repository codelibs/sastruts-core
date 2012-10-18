/*
 * Copyright 2009-2012 the Fess Project and the Others.
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

package org.codelibs.sastruts.core.filter;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codelibs.sastruts.core.SSCConstants;
import org.codelibs.sastruts.core.crypto.CachedCipher;
import org.codelibs.sastruts.core.entity.UserInfo;
import org.seasar.framework.container.SingletonS2Container;
import org.seasar.framework.util.StringUtil;

/**
 * A filter implementation to process a container based authentication.
 * 
 * @author shinsuke
 * 
 */
public class AuthFilter implements Filter {
    public List<Pattern> urlPatternList = new ArrayList<Pattern>();

    protected String cipherName;

    protected String loginPath;

    protected String adminRole;

    public void init(final FilterConfig filterConfig) throws ServletException {
        final String value = filterConfig.getInitParameter("urlPatterns");
        if (value != null) {
            final String[] urlPatterns = value.split(",");
            for (final String urlPattern : urlPatterns) {
                urlPatternList.add(Pattern.compile(urlPattern.trim()));
            }
        }

        cipherName = filterConfig.getInitParameter("cipherName");
        if (StringUtil.isBlank(cipherName)) {
            cipherName = "authCipher";
        }
        loginPath = filterConfig.getInitParameter("loginPath");
    }

    public void destroy() {
        urlPatternList = null;
        cipherName = null;
    }

    public void doFilter(final ServletRequest request,
            final ServletResponse response, final FilterChain chain)
            throws IOException, ServletException {
        final HttpServletRequest req = (HttpServletRequest) request;
        final HttpServletResponse res = (HttpServletResponse) response;
        final String uri = req.getRequestURI();
        final CachedCipher fessCipher = getCachedCipher();
        for (final Pattern pattern : urlPatternList) {
            final Matcher matcher = pattern.matcher(uri);
            if (matcher.matches()) {
                // require authentication
                boolean redirectLogin = false;
                final Object obj =
                    req.getSession().getAttribute(SSCConstants.USER_INFO);
                if (obj == null || !(obj instanceof UserInfo)) {
                    redirectLogin = true;
                }
                if (redirectLogin) {
                    final StringBuilder buf = new StringBuilder(256);
                    buf.append(System.currentTimeMillis());
                    buf.append('|');
                    buf.append(req.getRequestURL());

                    String encoding = request.getCharacterEncoding();
                    if (encoding == null) {
                        encoding = "UTF-8";
                    }

                    final StringBuilder urlBuf = new StringBuilder(1000);
                    if (StringUtil.isBlank(loginPath)) {
                        final String contextPath = req.getContextPath();
                        if (contextPath != null) {
                            urlBuf.append(contextPath);
                        }
                        urlBuf.append("/login/");
                    } else {
                        urlBuf.append(res.encodeURL(loginPath));
                    }
                    urlBuf.append("?returnPath=");
                    urlBuf.append(URLEncoder.encode(
                            fessCipher.encryptoText(buf.toString()), encoding));

                    // redirect
                    res.sendRedirect(urlBuf.toString());
                    return;
                }
            }
        }

        chain.doFilter(request, response);
    }

    protected CachedCipher getCachedCipher() {
        return SingletonS2Container.getComponent(cipherName);
    }

}
