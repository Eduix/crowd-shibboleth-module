/*
 * Copyright (c) 2012 Eduix Oy
 * All rights reserved
 */
package net.nordu.crowd.shibboleth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * Authentication Success Handler that uses the SavedRequest for redirection if
 * one is available and otherwise lets the user pass through to the currently
 * requested url
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class SavedRequestAwarePassThroughAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
        // Build the target url from the current url. Get the request URI without context path
        // and append query params if needed
        String uri = request.getRequestURI().substring(request.getContextPath().length());
        if (request.getQueryString() != null) {
            return uri + "?" + request.getQueryString();
        }
        return uri;
    }
}
