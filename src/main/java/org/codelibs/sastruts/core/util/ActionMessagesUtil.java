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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.struts.Globals;
import org.apache.struts.action.ActionMessage;
import org.apache.struts.action.ActionMessages;

/**
 * ActionMessages Utility.
 * 
 * @author shinsuke
 * 
 */
public final class ActionMessagesUtil {

    private ActionMessagesUtil() {
    }

    /**
     * Add a message by a message key to a request.
     * 
     * @param request
     * @param key
     */
    public static void addMessage(final HttpServletRequest request,
            final String key) {
        addMessage(request, key, new Object[0]);
    }

    /**
     * Add a message by a message key to a request.
     * 
     * @param request
     * @param key
     * @param values
     */
    public static void addMessage(final HttpServletRequest request,
            final String key, final Object... values) {
        final ActionMessages msgs = new ActionMessages();
        msgs.add(ActionMessages.GLOBAL_MESSAGE, new ActionMessage(key, values));
        addMessages(request, msgs);
    }

    /**
     * Add a message by a message key to a session.
     * 
     * @param session
     * @param key
     */
    public static void addMessage(final HttpSession session, final String key) {
        addMessage(session, key, new Object[0]);
    }

    /**
     * Add a message by a message key to a session.
     * 
     * @param session
     * @param key
     * @param values
     */
    public static void addMessage(final HttpSession session, final String key,
            final Object... values) {
        final ActionMessages msgs = new ActionMessages();
        msgs.add(ActionMessages.GLOBAL_MESSAGE, new ActionMessage(key, values));
        addMessages(session, msgs);
    }

    /**
     * Add an error message by a message key to a request.
     * 
     * @param request
     * @param key
     */
    public static void addError(final HttpServletRequest request,
            final String key) {
        addError(request, key, new Object[0]);
    }

    /**
     * Add an error message by a message key to a request.
     * 
     * @param request
     * @param key
     * @param values
     */
    public static void addError(final HttpServletRequest request,
            final String key, final Object... values) {
        final ActionMessages msgs = new ActionMessages();
        msgs.add(ActionMessages.GLOBAL_MESSAGE, new ActionMessage(key, values));
        addErrors(request, msgs);
    }

    /**
     * Add an error message by a message key to a session.
     * 
     * @param session
     * @param key
     */
    public static void addError(final HttpSession session, final String key) {
        addError(session, key, new Object[0]);
    }

    /**
     * Add an error message by a message key to a session.
     * 
     * @param session
     * @param key
     * @param values
     */
    public static void addError(final HttpSession session, final String key,
            final Object... values) {
        final ActionMessages msgs = new ActionMessages();
        msgs.add(ActionMessages.GLOBAL_MESSAGE, new ActionMessage(key, values));
        addErrors(session, msgs);
    }

    // From SAStruts

    /**
     * エラーメッセージをリクエストに保存します。
     * 
     * @param request
     *            リクエスト
     * @param errors
     *            エラーメッセージ
     * 
     */
    public static void saveErrors(HttpServletRequest request,
            ActionMessages errors) {
        if ((errors == null) || errors.isEmpty()) {
            request.removeAttribute(Globals.ERROR_KEY);
            return;
        }
        request.setAttribute(Globals.ERROR_KEY, errors);
    }

    /**
     * エラーメッセージをセッションに保存します。
     * 
     * @param session
     *            セッション
     * @param errors
     *            エラーメッセージ
     * 
     */
    public static void saveErrors(HttpSession session, ActionMessages errors) {
        if ((errors == null) || errors.isEmpty()) {
            session.removeAttribute(Globals.ERROR_KEY);
            return;
        }
        session.setAttribute(Globals.ERROR_KEY, errors);
    }

    /**
     * メッセージをリクエストに保存します。
     * 
     * @param request
     *            リクエスト
     * @param messages
     *            メッセージ
     * 
     */
    public static void saveMessages(HttpServletRequest request,
            ActionMessages messages) {
        if ((messages == null) || messages.isEmpty()) {
            request.removeAttribute(Globals.MESSAGE_KEY);
            return;
        }
        request.setAttribute(Globals.MESSAGE_KEY, messages);
    }

    /**
     * メッセージをセッションに保存します。
     * 
     * @param session
     *            セッション
     * @param messages
     *            メッセージ
     * 
     */
    public static void saveMessages(HttpSession session, ActionMessages messages) {
        if ((messages == null) || messages.isEmpty()) {
            session.removeAttribute(Globals.MESSAGE_KEY);
            return;
        }
        session.setAttribute(Globals.MESSAGE_KEY, messages);
    }

    /**
     * エラーメッセージをリクエストに追加します。
     * 
     * @param request
     *            リクエスト
     * @param errors
     *            エラーメッセージ
     * 
     */
    public static void addErrors(HttpServletRequest request,
            ActionMessages errors) {
        if (errors == null) {
            return;
        }
        ActionMessages requestErrors =
            (ActionMessages) request.getAttribute(Globals.ERROR_KEY);
        if (requestErrors == null) {
            requestErrors = new ActionMessages();
        }
        requestErrors.add(errors);
        saveErrors(request, requestErrors);
    }

    /**
     * エラーメッセージをセッションに追加します。
     * 
     * @param session
     *            セッション
     * @param errors
     *            エラーメッセージ
     * 
     */
    public static void addErrors(HttpSession session, ActionMessages errors) {
        if (errors == null) {
            return;
        }
        ActionMessages sessionErrors =
            (ActionMessages) session.getAttribute(Globals.ERROR_KEY);
        if (sessionErrors == null) {
            sessionErrors = new ActionMessages();
        }
        sessionErrors.add(errors);
        saveErrors(session, sessionErrors);
    }

    /**
     * エラーメッセージがあるかどうかを返します。
     * 
     * @param request
     *            リクエスト
     * @return エラーメッセージがあるかどうか
     * @since 1.0.4
     */
    public static boolean hasErrors(HttpServletRequest request) {
        ActionMessages errors =
            (ActionMessages) request.getAttribute(Globals.ERROR_KEY);
        if (errors != null && !errors.isEmpty()) {
            return true;
        }
        return false;
    }

    /**
     * メッセージをリクエストに追加します。
     * 
     * @param request
     *            リクエスト
     * @param messages
     *            メッセージ
     * 
     */
    public static void addMessages(HttpServletRequest request,
            ActionMessages messages) {
        if (messages == null) {
            return;
        }
        ActionMessages requestMessages =
            (ActionMessages) request.getAttribute(Globals.MESSAGE_KEY);
        if (requestMessages == null) {
            requestMessages = new ActionMessages();
        }
        requestMessages.add(messages);
        saveMessages(request, requestMessages);
    }

    /**
     * メッセージをセッションに追加します。
     * 
     * @param session
     *            セッション
     * @param messages
     *            メッセージ
     * 
     */
    public static void addMessages(HttpSession session, ActionMessages messages) {
        if (messages == null) {
            return;
        }
        ActionMessages sessionMessages =
            (ActionMessages) session.getAttribute(Globals.MESSAGE_KEY);
        if (sessionMessages == null) {
            sessionMessages = new ActionMessages();
        }
        sessionMessages.add(messages);
        saveMessages(session, sessionMessages);
    }
}
