/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.token;

import static java.lang.Boolean.FALSE;

public class TokenConstants {

    public static final String REQUEST_TOKEN_FORMAT = "token_format";
    public static final String OPAQUE = "opaque";
    public static final String EXPIRES_IN = "expires_in";

    public static boolean isClientOverrideAllowed() {
        return clientOverride.get();
    }

    public static void setClientOverride(boolean override) {
        clientOverride.set(override);
    }

    private static ThreadLocal<Boolean> clientOverride = new ThreadLocal<Boolean>() {
        @Override
        protected Boolean initialValue() {
            return FALSE;
        }
    };

}
