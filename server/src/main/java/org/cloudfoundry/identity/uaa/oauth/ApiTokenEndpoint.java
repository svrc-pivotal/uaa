/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth;


import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.EMPTY_LIST;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.util.StringUtils.hasText;

@Controller
public class ApiTokenEndpoint {

    private UaaUserDatabase userDatabase;
    private AuthorizationServerTokenServices tokenServices;
    private ClientDetailsService clientDetailsService;
    private OAuth2RequestFactory requestFactory;

    public ApiTokenEndpoint(ClientDetailsService clientDetailsService, OAuth2RequestFactory requestFactory, AuthorizationServerTokenServices tokenServices, UaaUserDatabase userDatabase) {
        this.clientDetailsService = clientDetailsService;
        this.requestFactory = requestFactory;
        this.tokenServices = tokenServices;
        this.userDatabase = userDatabase;
    }

    @RequestMapping(value = "/api_token", method = RequestMethod.POST)
    @ResponseBody
    public OAuth2AccessToken apiToken(@RequestParam(name = "client_id") String clientId,
                                      @RequestParam(name = "scopes", required = false, defaultValue = "") List<String> scopes,
                                      @RequestParam(name = "expires_in", required = false, defaultValue = "-1") int expiresIn,
                                      @RequestParam(name = "audience", required = false, defaultValue = "") List<String> audience,
                                      Authentication authentication,
                                      HttpServletRequest servletRequest) {
        OAuth2Authentication auth = validateOauth2Authentication(authentication);
        ClientDetails client = validateClient(clientId);
        UaaPrincipal principal = validatePrincipal(auth);
        UaaUser user = validateUser(principal);


        Map<String, String> parameters = new HashMap();
        parameters.put(OAuth2Utils.GRANT_TYPE, "password"); //TODO determine if a new grant type is needed
        parameters.put(OAuth2Utils.CLIENT_ID, client.getClientId());
        parameters.put(OAuth2Utils.RESPONSE_TYPE,"token");
        parameters.put(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE);
        if (expiresIn>0) {
            parameters.put(TokenConstants.EXPIRES_IN, String.valueOf(expiresIn));
        }


        Authentication uaaAuthentication = new UaaAuthentication(principal, EMPTY_LIST, new UaaAuthenticationDetails(servletRequest));
        OAuth2Authentication tokenRequest = new OAuth2Authentication(requestFactory.createAuthorizationRequest(parameters).createOAuth2Request(), uaaAuthentication);
        return tokenServices.createAccessToken(tokenRequest);
    }

    protected UaaUser validateUser(UaaPrincipal principal) {
        try {
            return userDatabase.retrieveUserById(principal.getId());
        } catch (UsernameNotFoundException e) {
            throw new BadRequestException("Unable to validate user.");
        }
    }

    protected OAuth2Authentication validateOauth2Authentication(Authentication authentication) {
        if (authentication!=null && authentication instanceof OAuth2Authentication) {
            return (OAuth2Authentication)authentication;
        }
        throw new BadRequestException("Invalid authentication type:"+ (authentication==null ? "null" : authentication.getClass().getName()));
    }

    protected ClientDetails validateClient(String clientId) {
        if (!hasText(clientId)) {
            throw new BadRequestException("Missing client_id");
        }
        try {
            ClientDetails result = clientDetailsService.loadClientByClientId(clientId);
            return result;
        } catch (ClientRegistrationException e) {
            throw new BadRequestException("Invalid client_id:"+clientId);
        }
    }

    protected UaaPrincipal validatePrincipal(OAuth2Authentication authentication) {
        if (authentication.getPrincipal()!=null && authentication.getPrincipal() instanceof UaaPrincipal) {
            return (UaaPrincipal) authentication.getPrincipal();
        }
        throw new BadRequestException("Invalid principal type:"+ (authentication.getPrincipal()==null ? "null" : authentication.getPrincipal().getClass().getName()));
    }

    @ResponseStatus(BAD_REQUEST)
    public class BadRequestException extends RuntimeException {
        private final int code;
        public BadRequestException(String message) {
            super();
            this.code = BAD_REQUEST.value();
        }

        @Override
        public String toString() {
            return new StringBuilder("error\"")
                .append(code)
                .append("\", error_description=\"")
                .append(getMessage())
                .append("\"")
                .toString();
        }
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public AuthorizationServerTokenServices getTokenServices() {
        return tokenServices;
    }

    public UaaUserDatabase getUserDatabase() {
        return userDatabase;
    }

}
