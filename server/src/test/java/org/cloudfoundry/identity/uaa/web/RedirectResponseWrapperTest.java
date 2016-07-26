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

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletWebRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


public class RedirectResponseWrapperTest {


    private HttpServletResponse response;
    private AbsoluteRedirectFilter.RedirectResponseWrapper wrapper;
    private IdentityZone zone;
    private ServletWebRequest attributes;
    private HttpServletRequest request;

    @Before
    public void setup() {
        clearThreadLocals();
        response = mock(HttpServletResponse.class);
        request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn("/uaa");
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080/uaa/"));
        when(request.getHeaderNames()).thenReturn(new SimpleEnumerator(Arrays.asList("Host")));
        when(request.getHeader("Host")).thenReturn("localhost");
        when(request.getHeaders("Host")).thenReturn(new SimpleEnumerator(Arrays.asList("localhost")));
        attributes = new ServletWebRequest(request);
        RequestContextHolder.setRequestAttributes(attributes);
        wrapper = new AbsoluteRedirectFilter.RedirectResponseWrapper(response);
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        zone = MultitenancyFixture.identityZone(generator.generate(), generator.generate());
    }



    @After
    public void clearThreadLocals() {
        IdentityZoneHolder.clear();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    public void send_relative_redirect() throws Exception {
        wrapper.sendRedirect("/");
        ArgumentCaptor<String> redirect = ArgumentCaptor.forClass(String.class);
        verify(response, times(1)).sendRedirect(redirect.capture());
        assertEquals("http://localhost:8080/uaa/", redirect.getValue());
    }

    @Test
    public void send_absolute_redirect() throws Exception {
        String location = "https://some.other.host/uaa/";
        wrapper.sendRedirect(location);
        ArgumentCaptor<String> redirect = ArgumentCaptor.forClass(String.class);
        verify(response, times(1)).sendRedirect(redirect.capture());
        assertEquals(location, redirect.getValue());
    }

    @Test
    public void get_correct_uaa_host() {
        assertEquals("localhost", UaaUrlUtils.getUaaHost());
    }


    class SimpleEnumerator implements Enumeration<String> {
        private List<String> items;

        public SimpleEnumerator(List<String> items) {
            this.items = new ArrayList<>(items);
        }

        @Override
        public boolean hasMoreElements() {
            return items.size()>0;
        }

        @Override
        public String nextElement() {
            String next = items.remove(0);
            return next;
        }
    }
}