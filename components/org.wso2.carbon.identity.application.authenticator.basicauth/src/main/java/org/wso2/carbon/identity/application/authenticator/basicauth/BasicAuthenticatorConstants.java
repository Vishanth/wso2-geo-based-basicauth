/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.basicauth;

/**
 * Constants used by the BasicAuthenticator
 */
public abstract class BasicAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "BasicAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "geobasedbasic";
    public static final String USER_NAME = "username";
    public static final String PASSWORD = "password";
    public static final String FAILED_USERNAME = "&failedUsername=";
    public static final String ERROR_CODE = "&errorCode=";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String UTF_8 = "UTF-8";

    public static final String AXIS2 = "axis2.xml";
    public static final String AXIS2_FILE = "repository/conf/axis2/axis2.xml";
    public static final String TRANSPORT_MAILTO = "mailto";

    public static final String AUTHORIZED_COUNTRY = "Brazil";

    public static final String GEO_ALERT_EMAIL_TEMPLATE = "GeoAlert";

    public static final String EMAIL_CLAIM = "http://wso2.org/claims/emailaddress";
    public static final String RECEIVER_EMAIL = "emailFromProfile";

    private BasicAuthenticatorConstants() {
    }
}
