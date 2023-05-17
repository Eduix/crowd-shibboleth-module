/*
 * Copyright (c) 2011, NORDUnet A/S
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

import com.atlassian.config.HomeLocator;
import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.ObjectNotFoundException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.integration.Constants;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelperImpl;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractor;
import com.atlassian.crowd.integration.http.util.CrowdHttpValidationFactorExtractorImpl;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationToken;
import com.atlassian.crowd.manager.application.ApplicationAccessDeniedException;
import com.atlassian.crowd.manager.application.ApplicationManager;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.manager.property.PropertyManager;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.crowd.model.application.RemoteAddress;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.user.User;
import com.atlassian.plugin.webresource.WebResourceManager;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.nordu.crowd.shibboleth.config.Configuration;
import net.nordu.crowd.shibboleth.config.ConfigurationLoader;
import net.nordu.crowd.shibboleth.config.UsernameUtil;
import net.nordu.crowd.sso.token.MultiDomainTokenService;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Servlet for setting the SSO cookie and redirecting to the wanted destination
 *
 * @author juha
 */
public class SSOCookieServlet extends NORDUnetHtmlServlet {

   private static final Logger log = LoggerFactory.getLogger(SSOCookieServlet.class);
   private final ApplicationService applicationService;
   private final ApplicationManager applicationManager;
   private final TokenAuthenticationManager tokenAuthenticationManager;
   private final MultiDomainTokenService mdts;
   private final MultiDomainSSOConfiguration multiDomainConfig;
   private final CrowdHttpTokenHelper httpTokenHelper;
   private final PropertyManager propertyManager;
   private volatile Configuration config;
   public static final String REDIRECT_ATTRIBUTE = "ssocookie.redirect";

   public SSOCookieServlet(ApplicationService applicationService, ApplicationManager applicationManager,
           TokenAuthenticationManager tokenAuthenticationManager, WebResourceManager webResourceManager,
           MultiDomainTokenService mdts, HomeLocator homeLocator, PropertyManager propertyManager) {
      super(webResourceManager, homeLocator);
      this.applicationService = applicationService;
      this.applicationManager = applicationManager;
      this.tokenAuthenticationManager = tokenAuthenticationManager;
      this.mdts = mdts;
      this.propertyManager = propertyManager;
      CrowdHttpValidationFactorExtractor extractorImpl = CrowdHttpValidationFactorExtractorImpl.getInstance();
      this.httpTokenHelper = CrowdHttpTokenHelperImpl.getInstance(extractorImpl);
      multiDomainConfig = new MultiDomainSSOConfiguration();
      config = ConfigurationLoader.loadConfiguration();
   }

   @Override
   protected void doGet(HttpServletRequest req, HttpServletResponse res) throws ServletException, IOException {
      log.trace("Creating SSO cookie {}", req.getContextPath());
      String requestedApplicationName = null;
      String originalRequestUrl = req.getParameter("redirectTo");
      UserAuthenticationContext authCtx = new UserAuthenticationContext();
      String remoteUser = req.getHeader("REMOTE_USER");
      if (config.isHeadersUrldecode()) {
         remoteUser = urlDecode(remoteUser);
      }
      String username = UsernameUtil.getFinalUsername(remoteUser, config);
      if (username == null) {
         username = req.getRemoteUser();
      }
      if (username == null || (username != null && username.length() == 0)) {
         log.error("No REMOTE_USER header");
         errorPage(res, "Unknown user");
         return;
      }

      List<Application> applications = null;
      boolean hasEmailAddress = false;
      try {
         final User user = applicationService.findUserByName(applicationManager.findByName("crowd"), username);
         applications = tokenAuthenticationManager.findAuthorisedApplications(user, "crowd");
         hasEmailAddress = !StringUtils.isBlank(user.getEmailAddress());
      } catch (ObjectNotFoundException e) {
         log.error("Could not find user", e);
      } catch (DirectoryNotFoundException e) {
         log.error("Could not find directory", e);
      } catch (OperationFailedException e) {
         log.error("Could not find the user or his authorised applications", e);
      }

      URL reqURL = null;
      // Try to guess the application we want to set the cookie for
      try {
         reqURL = new URL(originalRequestUrl);
         if (applications != null) {
            for (Application app : applications) {
               Set<RemoteAddress> remoteAddresses = app.getRemoteAddresses();
               for (RemoteAddress address : remoteAddresses) {
                  if (address.getAddress().equals(reqURL.getHost())) {
                     requestedApplicationName = app.getName();
                     break;
                  }
               }
            }
         }
      } catch (MalformedURLException e) {
      }
      if (originalRequestUrl == null || originalRequestUrl.trim().length() == 0) {
         requestedApplicationName = "crowd";
      }

      if (requestedApplicationName == null) {
    	 res.setContentType("text/html;charset=UTF-8");
         res.setStatus(HttpServletResponse.SC_FORBIDDEN);
         String error;
         try {
            error = "Not permitted to use service at " + (new URL(originalRequestUrl)).getHost();
         } catch (MalformedURLException e) {
            error = "Not permitted";
         }

         writeCustomError(res.getWriter(), error, ServletError.NOT_PERMITTED, error);
         return;
      }
      log.debug("Requested application name is {} and user does seem to have access", requestedApplicationName);

      authCtx.setName(username);
      authCtx.setApplication(requestedApplicationName);

      ValidationFactor[] validationFactors = httpTokenHelper.getValidationFactorExtractor().getValidationFactors(req).toArray(new ValidationFactor[0]);
      authCtx.setValidationFactors(validationFactors);
      CrowdSSOAuthenticationToken crowdAuthRequest = null;
      try {
         crowdAuthRequest = new CrowdSSOAuthenticationToken(tokenAuthenticationManager.authenticateUserWithoutValidatingPassword(applicationManager.findByName("crowd"), authCtx).getRandomHash());
      } catch (InvalidAuthenticationException e) {
         log.error("Invalid authentication", e);
         errorPage(res, e.getMessage());
         return;
      } catch (ApplicationAccessDeniedException e) {
         log.error("Access Denied: {}", e.getMessage());
         accessDeniedPage(res);
         return;
      } catch (InactiveAccountException e) {
         log.error("Account is inactive: {}", e.getMessage());
         errorPage(res, e.getMessage());
         return;
      } catch (ObjectNotFoundException e) {
         log.error("Object not found: {}", e.getMessage());
         accessDeniedPage(res);
         return;
      } catch (OperationFailedException e) {
         log.error("Could not authenticate user", e);
         errorPage(res, e.getMessage());
      }

      // fix for Confluence where the response filter is sometimes null.
      if (res != null && crowdAuthRequest != null && crowdAuthRequest.getCredentials() != null) {
         log.trace("Creating cookie");
         // create the cookie sent to the client
         Cookie tokenCookie = buildCookie(crowdAuthRequest.getCredentials().toString());

         if (log.isTraceEnabled()) {
            log.trace("Cookie: " + tokenCookie.getDomain() + " - " + tokenCookie.getName() + " " + tokenCookie.getValue());
         }
         res.addCookie(tokenCookie);
      } else {
         errorPage(res, null);
         return;
      }

      String referer = req.getHeader("referer");
      String gotoUrl = null;
      if (originalRequestUrl != null && originalRequestUrl.length() > 0) {
         gotoUrl = res.encodeRedirectURL(originalRequestUrl);
      } else {
         gotoUrl = res.encodeRedirectURL(referer);
      }
      boolean multiDomain = false;
      Set<String> multiDomainUrls = null;
      multiDomainConfig.reloadConfigIfNecessary();
      if (multiDomainConfig.isEnabled()) {
         multiDomainUrls = multiDomainConfig.getUrlsForApplications(applications);
         multiDomain = !multiDomainUrls.isEmpty();
      }
      if (multiDomain) {
         res.setContentType("text/html");
         PrintWriter writer = res.getWriter();
         writeHtmlStart(writer, "You are being logged in to all domains", null);
         writer.write("<h1>Multi Domain SSO</h1>");
         writer.write("<span id=\"logging-message\">Logging in to other domains...</span>");
         writer.write("<div id=\"sso-container\"></div>");
         writer.write("<script type=\"text/javascript\">");
         writer.write("SSO.config.goTo=\"" + gotoUrl + "\";");
         // Push domains to load into SSO.config.domains
         for (String multiDomainUrl : multiDomainUrls) {
            String token = mdts.createToken(crowdAuthRequest.getCredentials().toString());
            writer.write("SSO.config.urls.push(\"" + multiDomainUrl + "/crowd/plugins/servlet/setcookie?token=" + token + "\");");
         }
         if (!hasEmailAddress) {
            req.getSession().setAttribute(REDIRECT_ATTRIBUTE, gotoUrl);
            writer.write("SSO.config.hasEmail=false;");
         }
         writer.write("$(function(){SSO.load();});");
         writer.write("</script>");
         writeHtmlEnd(writer);
      } else {
         if (!hasEmailAddress) {
            req.getSession().setAttribute(REDIRECT_ATTRIBUTE, gotoUrl);
            String setEmailUrl = res.encodeRedirectURL("/crowd/plugins/servlet/setEmail");
            res.sendRedirect(setEmailUrl);
            return;
         }
         if (log.isTraceEnabled()) {
            log.trace("Redirecting to " + gotoUrl);
         }
         res.sendRedirect(gotoUrl);
      }
   }

   /**
    * Creates the cookie and sets attributes such as path, domain, and "secure" flag.
    *
    * @param token The SSO token to be included in the cookie
    */
   private Cookie buildCookie(String token) {
      Cookie tokenCookie = new Cookie(getCookieTokenKey(), token);

      // path
      tokenCookie.setPath(Constants.COOKIE_PATH);
      // domain
      if (propertyManager.getCookieConfiguration().getDomain() != null) {
         tokenCookie.setDomain(propertyManager.getCookieConfiguration().getDomain());
      }

      tokenCookie.setSecure(propertyManager.getCookieConfiguration().isSecure());

      return tokenCookie;
   }

   // TODO A real error page
   private void errorPage(HttpServletResponse res, String error) throws IOException {
	  res.setContentType("text/html;charset=UTF-8");
      PrintWriter writer = res.getWriter();
      if (error != null) {
         writeHtmlStart(writer, "Error setting SSO cookie", Collections.singletonList(error));
      } else {
         writeHtmlStart(writer, "Error setting SSO cookie", Collections.singletonList("Undefined error"));
      }
      writeHtmlEnd(writer);
   }

   private void accessDeniedPage(HttpServletResponse res) throws IOException {
	  res.setContentType("text/html;charset=UTF-8");
      res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You do not have access to the application");
   }

   public String getCookieTokenKey() {
      return propertyManager.getCookieConfiguration().getName();
   }

   @Override
   public String[] getRequiredResources() {
      return new String[]{"net.nordu.crowd.nordunet-sso:multidomainresources"};
   }

   @Override
   public boolean requiresResources() {
      return true;
   }
   
   private String urlDecode(String s) {
      if (s != null) {
         try {
            return URLDecoder.decode(s, "UTF-8");
         } catch (UnsupportedEncodingException e) {
            log.warn("Error decoding", e);
         }
      }
      return s;
   }
}
