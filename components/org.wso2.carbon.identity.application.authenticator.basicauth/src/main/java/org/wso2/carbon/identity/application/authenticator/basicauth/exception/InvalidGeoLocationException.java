package org.wso2.carbon.identity.application.authenticator.basicauth.exception;

import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.User;

public class InvalidGeoLocationException extends AuthenticationFailedException {
    private static final long serialVersionUID = 6368867653869262346L;

    public InvalidGeoLocationException(String message) { super(message); }

    public InvalidGeoLocationException(String message, User user) {
        super(message, user);
    }

    public InvalidGeoLocationException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidGeoLocationException(String message, User user, Throwable cause) {
        super(message, user, cause);
    }
}
