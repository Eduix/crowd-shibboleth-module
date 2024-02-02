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

import com.atlassian.config.HomeLocator;
import com.atlassian.plugin.webresource.UrlMode;
import com.atlassian.plugin.webresource.WebResourceManager;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;
import javax.servlet.http.HttpServlet;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * Base for NORDUnet HTML producing servlets. Has a default skin and template parts that can be overridden.</p>
 * <p>
 * Override files:
 * <ul>
 * <li> Html fragment for the header is read from %crowd-home%/ssoservlet/header.html</li>
 * <li> Html fragment for the footer is read from %crowd-home%/ssoservlet/footer.html</li>
 * <li> Plugin module keys for theme web resources are read from %crowd-home%/ssoservlet/themeResources.txt - to include
 * multiple web resources out them on separate lines. You need to install plugins that provide the plugin modules
 * <li> If these files are missing or can't be read then default NORDUnet values are used
 * </p>
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public abstract class NORDUnetHtmlServlet extends HttpServlet {

   private static final Logger log = LoggerFactory.getLogger(NORDUnetHtmlServlet.class);
   private static final String BODY_START_HTML_FRAGMENT = "header.html";
   private static final String BODY_END_HTML_FRAGMENT = "footer.html";
   private static final String THEME_RESOURCES = "themeResources.txt";
   private final WebResourceManager webResourceManager;
   private final HomeLocator homeLocator;
   private static final PolicyFactory POLICY_FACTORY = new HtmlPolicyBuilder().toFactory();

   public NORDUnetHtmlServlet(WebResourceManager webResourceManager, HomeLocator homeLocator) {
      this.webResourceManager = webResourceManager;
      this.homeLocator = homeLocator;
   }

   private String getHtmlFragment(String fragmentName) {
      File fragmentFile = new File(homeLocator.getHomePath() + File.separatorChar + "ssoservlet" + File.separatorChar + fragmentName);
      log.debug("Getting fragment {}", fragmentFile.getAbsolutePath());
      if (fragmentFile.exists() && fragmentFile.canRead()) {
         try {
            return FileUtils.readFileToString(fragmentFile);
         } catch (IOException e) {
            log.warn("Could not read html fragment {}: {}", fragmentFile.getAbsolutePath(), e.getMessage());
         }
      }
      return null;
   }

   private List<String> getThemeResources() {
      File themeResourcesFile = new File(homeLocator.getHomePath() + File.separatorChar + "ssoservlet" + File.separatorChar + THEME_RESOURCES);
      log.debug("Get theme resource {}", themeResourcesFile.getAbsolutePath());
      if (themeResourcesFile.exists() && themeResourcesFile.canRead()) {
         try {
            return FileUtils.readLines(themeResourcesFile);
         } catch (IOException e) {
            log.warn("Could not read theme resources file {}: {}", themeResourcesFile.getAbsolutePath(), e.getMessage());
         }
      }
      // If we could not find customised theme resources return NORDUnet servlet skin
      return Collections.singletonList("net.nordu.crowd.nordunet-sso:servletSkin");
   }

   protected void writeHtml(PrintWriter writer, String title, String content) {
      writeHtmlStart(writer, title, null);
      writer.write(content);
      writeHtmlEnd(writer);
   }

   protected void writeHtmlWithFragment(PrintWriter writer, String title, String fragmentName, String defaultText) {
      writeHtmlStart(writer, title, null);
      String fragment = getHtmlFragment(fragmentName);
      if (fragment != null) {
         writer.write(fragment);
      } else {
         writer.write(defaultText);
      }
      writeHtmlEnd(writer);
   }

   protected void writeHtmlStart(PrintWriter writer, String title, List<String> errors) {
      writeHtmlStart(writer, title, errors, null);
   }

   protected void writeCustomError(PrintWriter writer, String title, ServletError error, String errorText) {
      writeHtmlStart(writer, title, Collections.singletonList(errorText));
      String errorFragment = getHtmlFragment(error.getFragment());
      if (errorFragment != null) {
         writer.write(errorFragment);
      } else {
         writer.write(error.getDefaultContent());
      }
      writeHtmlEnd(writer);
   }

   protected void writeHtmlStart(PrintWriter writer, String title, List<String> errors, String headInclude) {      
      writer.write("<html><head><title>" + POLICY_FACTORY.sanitize(title) + "</title>");
      webResourceManager.requireResource("com.atlassian.auiplugin:ajs");
      for (String themeResource : getThemeResources()) {
         if (!StringUtils.isBlank(themeResource)) {
            webResourceManager.requireResource(themeResource);
         }
      }
      if (requiresResources()) {
         for (String resource : getRequiredResources()) {
            webResourceManager.requireResource(resource);
         }
      }
      webResourceManager.includeResources(writer, UrlMode.AUTO);
      if (headInclude != null) {
         writer.write(headInclude);
      }
      writer.write("</head><body>");
      String htmlFragment = getHtmlFragment(BODY_START_HTML_FRAGMENT);
      if (htmlFragment != null) {
         writer.write(htmlFragment);
      } else {
         writer.write("<div id='container'><div id='top'><h1 title='NORDUnet'>NORDUnet</h1></div><div id='content'>");
      }
      if (errors != null && !errors.isEmpty()) {
         writer.write("<div style='padding: 2px; background: #fcc; border:5px solid #f00; font-weight:bold;'>");
         writer.write("<p>Errors:</p>");
         writer.write("<ul>");
         for (String error : errors) {
            writer.append("<li>").append(POLICY_FACTORY.sanitize(error)).append("</li>");
         }
         writer.write("</ul></div>");
      }
   }

   public abstract String[] getRequiredResources();

   public abstract boolean requiresResources();

   protected void writeHtmlEnd(PrintWriter writer) {
      String htmlFragment = getHtmlFragment(BODY_END_HTML_FRAGMENT);
      if (htmlFragment != null) {
         writer.write(htmlFragment);
      } else {
         writer.write("</div><div id='footer'>");
         writer.write("<p>NORDUnet A/S | Kastruplundgade 22 | DK-2770 Kastrup | DENMARK | Phone +45 32 46 25 00 | Fax +45 45 76 23 66 | info@nordu.net</p></div></div>");
      }
      writer.write("</body></html>");
   }
}
