/*
 * Copyright (c) 2011 Eduix Oy
 * All rights reserved
 */
package net.nordu.crowd.sso;

import com.atlassian.config.HomeLocator;
import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.embedded.api.User;
import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.InvalidUserException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.crowd.manager.directory.DirectoryPermissionException;
import com.atlassian.crowd.model.user.UserTemplate;
import com.atlassian.crowd.service.UserService;
import com.atlassian.plugin.webresource.WebResourceManager;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;

/**
 * Servlet to let users set their email address if it's not set already
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class SetMailAddressServlet extends NORDUnetHtmlServlet {

    private final UserService userService;
    private final DirectoryManager directoryManager;

    public SetMailAddressServlet(WebResourceManager webResourceManager, UserService userService, DirectoryManager directoryManager, HomeLocator homeLocator) {
        super(webResourceManager, homeLocator);
        this.userService = userService;
        this.directoryManager = directoryManager;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            final String username = userService.getAuthenticatedUsername(req);
            if (username != null) {
                final Directory directory = directoryManager.findDirectoryByName("System users");
                final User user = directoryManager.findUserByName(directory.getId(), username);
                if (StringUtils.isBlank(user.getEmailAddress())) {
                    writeAddressForm(resp.getWriter());
                } else {
                    writeHtml(resp.getWriter(), "Set email address", "<div>Your email address is already set  (<strong>" + user.getEmailAddress() + "</strong>)</div>");
                }
            }
        } catch (DirectoryNotFoundException e) {
        } catch (UserNotFoundException e) {
        } catch (OperationFailedException e) {
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String email = req.getParameter("email");
        if (!StringUtils.isBlank(email)) {
            try {
                final String username = userService.getAuthenticatedUsername(req);
                if (username != null) {
                    final Directory directory = directoryManager.findDirectoryByName("System users");
                    final User user = directoryManager.findUserByName(directory.getId(), username);
                    UserTemplate mutableUser = new UserTemplate(user);
                    mutableUser.setEmailAddress(email);
                    directoryManager.updateUser(directory.getId(), mutableUser);
                    String redirectUrl = null;
                    if (req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE) != null) {
                        redirectUrl = (String) req.getSession().getAttribute(SSOCookieServlet.REDIRECT_ATTRIBUTE);
                    }
                    writeInfo(resp.getWriter(), redirectUrl);
                }
            } catch (DirectoryNotFoundException e) {
            } catch (UserNotFoundException e) {
            } catch (OperationFailedException e) {
            } catch (DirectoryPermissionException e) {
            } catch (InvalidUserException e) {
            }
        } else {
            writeAddressForm(resp.getWriter());
        }
    }

    private void writeAddressForm(PrintWriter writer) {
        writeHtmlStart(writer, "Set email address", null);
        writer.write("<form action=\"/crowd/plugins/servlet/setEmail\" method=\"post\">");
        writer.write("<p>Your IDP did not provide an email address for you. Please input your email address.</p>");
        writer.write("<input name=\"email\" type=\"text\"> <input type=\"submit\" value=\"Submit\" name=\"submit\">");
        writer.write("</form>");
        writeHtmlEnd(writer);
    }

    private void writeInfo(PrintWriter writer, String redirectUrl) {
        if (redirectUrl != null) {
            writeHtmlStart(writer, "Set email adress", null, "<meta http-equiv=\"refresh\" content=\"8;url=" + redirectUrl + "\">");
        } else {
            writeHtmlStart(writer, "Set email adress", null);
        }
        writer.write("<div><p>You email address has been set. ");
        if (redirectUrl != null) {
            writer.write("You will be redirected to your original destination in a matter of seconds. You can also proceed there <a href=\"" + redirectUrl + "\">immediately</a>");
        }
        writer.write("</p</div>");
        writeHtmlEnd(writer);
    }

    @Override
    public String [] getRequiredResources() {
        return null;
    }

    @Override
    public boolean requiresResources() {
        return false;
    }
}
