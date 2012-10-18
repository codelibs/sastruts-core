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
package org.codelibs.sastruts.core.interceptor;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.aopalliance.intercept.MethodInvocation;
import org.codelibs.sastruts.core.SSCConstants;
import org.codelibs.sastruts.core.annotation.UserInfo;
import org.seasar.framework.aop.S2MethodInvocation;
import org.seasar.framework.aop.interceptors.AbstractInterceptor;
import org.seasar.framework.beans.BeanDesc;
import org.seasar.framework.beans.PropertyDesc;
import org.seasar.framework.beans.factory.BeanDescFactory;
import org.seasar.struts.util.RequestUtil;

/**
 * 
 * @author shinsuke
 * 
 */
public class UserInfoInterceptor extends AbstractInterceptor {

    /*
     * (non-Javadoc)
     * 
     * @see
     * org.aopalliance.intercept.MethodInterceptor#invoke(org.aopalliance.intercept
     * .MethodInvocation)
     */
    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        HttpServletRequest request = RequestUtil.getRequest();
        HttpSession session = request.getSession(false);
        if (session == null) {
            return invocation.proceed();
        }
        Object userInfoObj = session.getAttribute(SSCConstants.USER_INFO);
        if (userInfoObj == null) {
            return invocation.proceed();
        }

        Object target = invocation.getThis();
        Class<?> clazz = ((S2MethodInvocation) invocation).getTargetClass();
        BeanDesc beanDesc = BeanDescFactory.getBeanDesc(clazz);
        int size = beanDesc.getPropertyDescSize();
        for (int i = 0; i < size; i++) {
            PropertyDesc propertyDesc = beanDesc.getPropertyDesc(i);
            Method readMethod = propertyDesc.getReadMethod();
            if (readMethod != null
                && readMethod.isAnnotationPresent(UserInfo.class)) {
                propertyDesc.setValue(target, userInfoObj);
                break;
            }
            Field field = propertyDesc.getField();
            if (field != null && field.isAnnotationPresent(UserInfo.class)) {
                propertyDesc.setValue(target, userInfoObj);
                break;
            }
        }
        return invocation.proceed();
    }

}
