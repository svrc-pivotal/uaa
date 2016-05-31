/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.getClientCredentialsOAuthAccessToken;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class ApiTokenEndpointMockMvcTests extends InjectedMockContextTest {

    private String adminToken;
    private String apiClientToken;
    private RevocableTokenProvisioning tokenProvisioning;
    private BaseClientDetails apiClient;
    private ScimUser apiUser;
    private String userToken;

    @Before
    public void setUpContext() throws Exception {
        IdentityZoneHolder.clear();

        adminToken =
            getClientCredentialsOAuthAccessToken(
                getMockMvc(),
                "admin",
                "adminsecret",
                "uaa.admin",
                null
            );
        tokenProvisioning = (RevocableTokenProvisioning) getWebApplicationContext().getBean("revocableTokenProvisioning");

        apiClient = MockMvcUtils.setUpClients(getWebApplicationContext().getBean(JdbcClientDetailsService.class),
                                              "api_token_"+new RandomValueStringGenerator(6),
                                              "uaa.api.token",
                                              "uaa.api.token",
                                              "password,client_credentials",
                                              false,
                                              null,
                                              null,
                                              300);
        apiClientToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(getMockMvc(),apiClient.getClientId(),
                                                                           MockMvcUtils.SECRET,
                                                                           "uaa.api.token",
                                                                           null);

        ScimUser scimUser = new ScimUser();
        scimUser.setUserName("api-user-"+new RandomValueStringGenerator().generate()+"@api.test.com");
        ScimUser.Email email = new ScimUser.Email();
        email.setValue(scimUser.getUserName());
        scimUser.setEmails(Arrays.asList(email));
        apiUser = getWebApplicationContext().getBean(ScimUserProvisioning.class).createUser(scimUser, "secret");
        userToken = MockMvcUtils.getUserOAuthAccessTokenAuthCode(getMockMvc(),
                                                                 "identity",
                                                                 "identitysecret",
                                                                 apiUser.getId(),
                                                                 apiUser.getUserName(),
                                                                 "secret",
                                                                 "uaa.api.token");

    }

    @After
    public void clearUp() {
        SecurityContextHolder.clearContext();
    }

    private IdentityZone setupIdentityZone(String subdomain) {
        return MockMvcUtils.setupIdentityZone(
            getWebApplicationContext().getBean(IdentityZoneProvisioning.class),
            subdomain
        );
    }

    @Test
    public void client_credentials_uaa_admin() throws Exception {
        getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+adminToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
                .param(OAuth2Utils.CLIENT_ID, "cf")
        )
            .andExpect(status().isForbidden());
    }

    @Test
    public void invalid_client_id() throws Exception {
        getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+userToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
                .param(OAuth2Utils.CLIENT_ID, "xxx")
        )
            .andExpect(status().isBadRequest());
    }

    @Test
    public void missing_client_id() throws Exception {
        getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+userToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
        )
            .andExpect(status().isBadRequest());
    }

    @Test
    public void client_credentials_api_token_scope() throws Exception {
        getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+apiClientToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
                .param(OAuth2Utils.CLIENT_ID, "cf")
        )
            .andExpect(status().isForbidden());
    }

    @Test
    public void inactive_user_id() throws Exception {
        apiUser.setActive(false);
        getWebApplicationContext().getBean(ScimUserProvisioning.class).update(apiUser.getId(), apiUser);
        getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer "+userToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
                .param(OAuth2Utils.CLIENT_ID, "cf")
        )
            .andExpect(status().isUnauthorized());
    }

    @Test
    public void get_api_token_as_api_token_scope() throws Exception {
        long expiresAt = (200*1000 + System.currentTimeMillis());
        MvcResult result = getMockMvc().perform(
            post("/api_token")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .accept(MediaType.APPLICATION_JSON)
                .param(OAuth2Utils.CLIENT_ID, "cf")
                .param(TokenConstants.EXPIRES_IN, "200")
        )
            .andExpect(status().isOk())
            .andReturn();
        validateTokenResult(result, expiresAt);
    }

    public void validateTokenResult(MvcResult result, long expiresAt) throws Exception {
        String content = result.getResponse().getContentAsString();
        assertNotNull("JSON result expected", content);
        OAuth2AccessToken token = JsonUtils.readValue(content, OAuth2AccessToken.class);
        assertNotNull("Expected token value in JSON body", token);
        String value = token.getValue();
        assertFalse("Token should be opaque", UaaTokenUtils.isJwtToken(value));
        RevocableToken revocableToken = tokenProvisioning.retrieve(value);
        assertNotNull("Token should be revocable", revocableToken);
        //validate within 10 seconds is ok.
        assertEquals("Token should expire at:"+expiresAt, expiresAt/10000, (revocableToken.getExpiresAt()/10000));


    }


}
