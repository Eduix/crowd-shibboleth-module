/*
 * Copyright (c) 2012, NORDUnet A/S
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 *  * Neither the name of the NORDUnet nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.nordu.crowd.sso;

import com.atlassian.crowd.integration.Constants;
import com.atlassian.crowd.manager.property.PropertyManager;
import com.atlassian.crowd.manager.property.PropertyManagerException;
import com.atlassian.crowd.service.client.ClientProperties;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.nordu.crowd.sso.token.InvalidTokenException;
import net.nordu.crowd.sso.token.MultiDomainTokenService;
import net.nordu.crowd.sso.token.Token;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet for setting the SSO cookie for multiple domain via image loading.
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class SetSSOCookieServlet extends HttpServlet {

   private static final Logger log = LoggerFactory.getLogger(SetSSOCookieServlet.class);
   /* PIXEL_B64 is a base64 encoded representation of a 1x1 transparent gif
    * See http://matthew.mceachen.us/blog/how-to-serve-a-transparent-1x1-pixel-gif-from-a-servlet-711.html
    */
   private static final String PIXEL_B64 = "R0lGODlhAQABAPAAAAAAAAAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";
   private static final byte[] PIXEL_BYTES = Base64.decode(PIXEL_B64);
   private final ClientProperties clientProperties;
   private final PropertyManager propertyManager;
   private final MultiDomainTokenService mdts;

   public SetSSOCookieServlet(ClientProperties clientProperties, MultiDomainTokenService mdts, PropertyManager propertyManager) {
      this.clientProperties = clientProperties;
      this.mdts = mdts;
      this.propertyManager = propertyManager;
   }

   @Override
   protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      String tokenString = req.getParameter("token");
      try {
         Token token = mdts.consumeToken(tokenString);
         Cookie cookie = new Cookie(clientProperties.getCookieTokenKey(), token.getCookieToken());
         cookie.setPath(Constants.COOKIE_PATH);
         String domain = dropSubDomainFromHost(req);
         if (domain != null) {
            cookie.setDomain(domain);
         }
         try {
            cookie.setSecure(propertyManager.isSecureCookie());
         } catch (PropertyManagerException e) {
            log.warn("Error setting secure property of cookie", e);
            cookie.setSecure(Boolean.FALSE);
         }
         resp.addCookie(cookie);
      } catch (InvalidTokenException e) {
         log.warn("Invalid token found: {}", e.getMessage());
         resp.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
      }
      // Set standard HTTP/1.1 no-cache headers
      resp.setHeader("Cache-Control", "private, no-store, no-cache, must-revalidate");
      // Set standard HTTP/1.0 no-cache header
      resp.setHeader("Pragma", "no-cache");
      resp.setContentType("image/gif");
      resp.getOutputStream().write(PIXEL_BYTES);
   }

   private String dropSubDomainFromHost(HttpServletRequest req) {
      String host = req.getLocalName();
      int dotCount = StringUtils.countMatches(host, ".");
      if (dotCount > 1) {
         // Drop the "most specific" part from the domain
         return host.substring(host.indexOf(".") + 1);
      }
      return null;
   }
}
