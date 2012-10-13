package org.codelibs.sastruts.core.entity;

import java.io.Serializable;

public class UserInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;

    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }
}
