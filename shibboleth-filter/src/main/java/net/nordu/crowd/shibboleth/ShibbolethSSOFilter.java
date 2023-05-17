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
package net.nordu.crowd.shibboleth;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpMethodParams;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

import com.atlassian.crowd.embedded.api.Directory;
import com.atlassian.crowd.embedded.api.PasswordCredential;
import com.atlassian.crowd.embedded.impl.IdentifierUtils;
import com.atlassian.crowd.exception.ApplicationNotFoundException;
import com.atlassian.crowd.exception.DirectoryNotFoundException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.InvalidCredentialException;
import com.atlassian.crowd.exception.InvalidGroupException;
import com.atlassian.crowd.exception.InvalidTokenException;
import com.atlassian.crowd.exception.InvalidUserException;
import com.atlassian.crowd.exception.MembershipAlreadyExistsException;
import com.atlassian.crowd.exception.MembershipNotFoundException;
import com.atlassian.crowd.exception.ObjectNotFoundException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.ReadOnlyGroupException;
import com.atlassian.crowd.exception.UserAlreadyExistsException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationDetails;
import com.atlassian.crowd.integration.springsecurity.CrowdSSOAuthenticationToken;
import com.atlassian.crowd.integration.springsecurity.RequestToApplicationMapper;
import com.atlassian.crowd.integration.springsecurity.user.CrowdUserDetails;
import com.atlassian.crowd.manager.application.ApplicationAccessDeniedException;
import com.atlassian.crowd.manager.application.ApplicationManager;
import com.atlassian.crowd.manager.application.ApplicationService;
import com.atlassian.crowd.manager.authentication.TokenAuthenticationManager;
import com.atlassian.crowd.manager.directory.DirectoryManager;
import com.atlassian.crowd.manager.directory.DirectoryPermissionException;
import com.atlassian.crowd.manager.property.PropertyManager;
import com.atlassian.crowd.model.application.Application;
import com.atlassian.crowd.model.authentication.UserAuthenticationContext;
import com.atlassian.crowd.model.authentication.ValidationFactor;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.model.group.GroupTemplate;
import com.atlassian.crowd.model.group.GroupType;
import com.atlassian.crowd.model.group.GroupWithAttributes;
import com.atlassian.crowd.model.token.Token;
import com.atlassian.crowd.model.user.User;
import com.atlassian.crowd.model.user.UserTemplate;
import com.atlassian.crowd.search.EntityDescriptor;
import com.atlassian.crowd.search.builder.QueryBuilder;
import com.atlassian.crowd.search.query.entity.restriction.NullRestrictionImpl;
import com.atlassian.crowd.search.query.membership.MembershipQuery;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.user.UserAuthoritiesProvider;

import net.nordu.crowd.shibboleth.config.Configuration;
import net.nordu.crowd.shibboleth.config.ConfigurationLoader;
import net.nordu.crowd.shibboleth.config.GroupMapper;
import net.nordu.crowd.shibboleth.config.UsernameUtil;

/**
 * Login filter which relies on headers sent by Shibboleth for user information
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class ShibbolethSSOFilter extends AbstractAuthenticationProcessingFilter {

   private static final Logger log = LoggerFactory.getLogger(ShibbolethSSOFilter.class);
   private static final String HOME_ORG_USER = "net.nordu.crowd.shibboleth.homeOrgUser";
   private ClientProperties clientProperties;
   private PropertyManager propertyManager;
   private CrowdHttpTokenHelper httpTokenHelper;
   private RequestToApplicationMapper requestToApplicationMapper;
   private ApplicationService applicationService;
   private ApplicationManager applicationManager;
   private UserAuthoritiesProvider userAuthoritiesProvider;
   private TokenAuthenticationManager tokenAuthenticationManager;
   private DirectoryManager directoryManager;
   private static Configuration config;
   private static SecureRandom prng;
   private static MessageDigest sha;

   static {
      config = ConfigurationLoader.loadConfiguration();
      try {
         prng = SecureRandom.getInstance("SHA1PRNG");
         sha = MessageDigest.getInstance("SHA-1");
      } catch (NoSuchAlgorithmException e) {
         log.error("Could not instantiate secure random number generator: {}", e.getMessage());
         throw new RuntimeException(e);
      }
   }

   public ShibbolethSSOFilter() {
      super("/j_spring_security_check");
   }

   @Override
   public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
      boolean newUser = false;
      String newUserPassword = null;

      if (log.isTraceEnabled()) {
         Enumeration headerNames = request.getHeaderNames();
         while (headerNames.hasMoreElements()) {
            String h = (String) headerNames.nextElement();
            log.trace(h + " - " + request.getHeader(h));
         }
      }
      this.checkReloadConfig();
      
      String remoteUser = request.getHeader("REMOTE_USER");
      if (config.isHeadersUrldecode()) {
         remoteUser = urlDecode(remoteUser);
      }
      String username = UsernameUtil.getFinalUsername(remoteUser, config);
      // If the username is not the same as the REMOTE_USER header the user
      // belongs to the home organizations and should be found in LDAP -
      // There is no need to create/update the user
      boolean homeOrgUser = remoteUser != null && !remoteUser.equals(username);
      request.setAttribute(HOME_ORG_USER, homeOrgUser);
      CrowdUserDetails userDetails = null;
      boolean groupsChanged = false;
      try {
         userDetails = loadUserByUsername(username);
         // User attributes and groups are not updated for home organization users
         if (!homeOrgUser) {
            try {
               Directory directory = directoryManager.findDirectoryByName(config.getDirectoryName());
               updateUserAttributes(username, request, directory);
               groupsChanged = updateUserGroups(username, request, directory);
            } catch (DirectoryNotFoundException e) {
               log.error("Could not find user directory {}", config.getDirectoryName());
            }
         }
      } catch (UserNotFoundException e) {
         if (homeOrgUser) {
            log.error("User presumed to be found from LDAP could not be found", e);
            return null;
         }
         // Otherwise no need to respond here, the user is created a few lines down
      } catch (ApplicationNotFoundException e) {
         // Not sure in which case this can come up while the system is
         // working correctly 
         log.error("Error loading user by username", e);
         return null;
      }

      if (userDetails == null) {
         if (!config.isCreateUser()) {
            log.warn("Tried to create a new user {}", remoteUser);
            return null;
         }
         log.debug("No user {} found. Creating", username);
         String firstName = request.getHeader(config.getFirstNameHeader());
         String lastName = request.getHeader(config.getLastNameHeader());
         String email = request.getHeader(config.getEmailHeader());

         if (config.isHeadersUrldecode()) {
            firstName = urlDecode(firstName);
            lastName = urlDecode(lastName);
            email = urlDecode(email);
         } else if (config.isLatin1ToUTF8()) {
            firstName = StringUtil.latin1ToUTF8(firstName);
            lastName = StringUtil.latin1ToUTF8(lastName);
         }

         newUserPassword = randomPassword();
         if (!createUser(username, firstName, lastName, email, newUserPassword, getUserAttributesFromHeaders(request))) {
            return null;
         } else {
            // Set groups for the user if he/she is not a home organisation user
            if (!homeOrgUser) {
               try {
                  Directory directory = directoryManager.findDirectoryByName(config.getDirectoryName());
                  updateUserGroups(username, request, directory);
               } catch (DirectoryNotFoundException e) {
                  log.error("Could not find user directory {}", config.getDirectoryName());
               }
            }
            newUser = true;
         }
      } else if (!homeOrgUser && config.isSyncEveryLogin() && groupsChanged) {
         // User needs to be resynced to applications and the requires
         // the user password so generate a new one - only do this if group
         // memberships have changed
         newUserPassword = randomPassword();
         try {
            Directory directory = directoryManager.findDirectoryByName(config.getDirectoryName());
            updateUserPassword(username, newUserPassword, directory);
         } catch (DirectoryNotFoundException e) {
            log.error("Could not find user directory {}", config.getDirectoryName());
         }
      }
      UserAuthenticationContext authCtx = new UserAuthenticationContext();
      authCtx.setApplication(clientProperties.getApplicationName());
      authCtx.setName(username);
      List<ValidationFactor> validationFactors = httpTokenHelper.getValidationFactorExtractor().getValidationFactors(request);
      ValidationFactor[] validationFactorArray = validationFactors.toArray(new ValidationFactor[0]);
      authCtx.setValidationFactors(validationFactorArray);

      if (log.isTraceEnabled()) {
         log.trace("Trying to log in as {} without a password", username);
      }
      try {
         Application application = applicationManager.findByName(clientProperties.getApplicationName());
         Token token = tokenAuthenticationManager.authenticateUserWithoutValidatingPassword(application, authCtx);
         token = tokenAuthenticationManager.validateUserToken(application, token.getRandomHash(), validationFactorArray);
         CrowdSSOAuthenticationToken crowdAuthRequest = new CrowdSSOAuthenticationToken(token.getRandomHash());
         doSetDetails(request, crowdAuthRequest);

         Authentication newAuth = getAuthenticationManager().authenticate(crowdAuthRequest);
         if (newAuth != null) {
            log.debug("Authentication: principal {} credentials {} isAuthenticated {}", newAuth.getPrincipal(), newAuth.getCredentials(), newAuth.isAuthenticated());
         }
         SecurityContextHolder.getContext().setAuthentication(newAuth);
      } catch (InvalidAuthenticationException | InactiveAccountException | ApplicationAccessDeniedException | OperationFailedException | ObjectNotFoundException | InvalidTokenException e) {
         log.error("Error authenticating user", e);
         return null;
      } catch (NullPointerException e) {
         log.error(e.getMessage(), e);
         return null;
      }

      if (newUser || (!homeOrgUser && config.isSyncEveryLogin() && groupsChanged)) {
         // Sync users to all necessary applications         
         if (config.syncRequired()) {
            HttpClient client = new HttpClient();
            // TODO: sync users only to applications they need to be synced to
            // (get their application list and fetch the urls for that list)
            log.info("Syncing user {} to all applications", username);
            for (String url : config.getAllUrls()) {
               GetMethod get = new GetMethod(url);
               get.setQueryString(new NameValuePair[]{
                  new NameValuePair("username", username),
                  new NameValuePair("password", newUserPassword)
               });
               get.getParams().setParameter(HttpMethodParams.SO_TIMEOUT, 5000);
               try {
                  int statusCode = client.executeMethod(get);
                  if (statusCode != HttpStatus.SC_OK) {
                     log.warn("Could not sync user {} using url {}", username, url);
                  }
               } catch (HttpException e) {
                  log.error("Fatal protocol violation. Could not sync user {} using url {}", username, url, e);
               } catch (IOException e) {
                  log.error("Fatal transport error Could not sync user {} using url {}", username, url, e);
               } finally {
                  get.releaseConnection();
               }
            }
         }
         // This session attribute is read by the SSO Cookie Servlet (part of
         // the NORDUnet Crowd SSO Plugin)
         request.getSession().setAttribute("new.user", newUser);
      }
      return SecurityContextHolder.getContext().getAuthentication();
   }

   /**
    * This filter will process all requests and check for Shibboleth headers to determine if user is logged in. If the
    * user is logged in but a user account does not exist in Crowd one will be made.
    *
    * @param request servlet request containing either username/password paramaters or the Crowd token as a cookie.
    * @param response servlet response to write out cookie.
    * @return <code>true</code> only if the filterProcessesUrl is in the request URI.
    */
   @Override
   protected boolean requiresAuthentication(final HttpServletRequest request, final HttpServletResponse response) {
      if (log.isTraceEnabled()) {
         Enumeration headerNames = request.getHeaderNames();
         while (headerNames.hasMoreElements()) {
            String h = (String) headerNames.nextElement();
            log.trace(h + " - " + request.getHeader(h));
         }
      }
      this.checkReloadConfig();
      log.debug("Checking if authentication is required");
      String remoteUser = request.getHeader("REMOTE_USER");
      if (config.isHeadersUrldecode()) {
         remoteUser = urlDecode(remoteUser);
      }
      String username = UsernameUtil.getFinalUsername(remoteUser, config);
      Authentication auth = SecurityContextHolder.getContext().getAuthentication();
      if (auth != null && !IdentifierUtils.equalsInLowerCase(((CrowdUserDetails) auth.getPrincipal()).getUsername(), username) && !StringUtils.isBlank(username)) {
         log.debug("User is authenticated but the username from authentication does "
                 + "not match username in request! Logging user out");
         try {
            SecurityContextHolder.clearContext();
            tokenAuthenticationManager.invalidateToken(httpTokenHelper.getCrowdToken(request, propertyManager.getCookieConfiguration().getName()));
         } catch (Exception e) {
            log.error("Could not logout SSO user from Crowd", e);
            return true;
         }
         return !StringUtils.isBlank(username);
      } else if (auth == null || !auth.isAuthenticated()) {
         // If the user is not authenticated and REMOTE_USER is set authentication is required
         log.debug("User is not authenticated. REMOTE_USER: {} - username: {}", remoteUser, username);
         //return !StringUtils.isBlank(username);
         return this.userRequiresAuthentication(username);
      } else {
         log.debug("User already authenticated");
      }
      return false;
   }
   
   private boolean userRequiresAuthentication(String username) {
      if (StringUtils.isBlank(username)) {
         return false;
      }
      try {
         CrowdUserDetails userDetails = loadUserByUsername(username);
         return userDetails.isEnabled();
      } catch (UserNotFoundException | ApplicationNotFoundException e) {
         return config.isCreateUser();
      }
   }

   private boolean createUser(String username, String firstname, String lastname, String email, String password, Map<String, Set<String>> attributes) {
      try {
         Directory directory = directoryManager.findDirectoryByName(config.getDirectoryName());
         UserTemplate template = new UserTemplate(username);
         template.setDirectoryId(directory.getId());
         template.setFirstName(firstname);
         template.setLastName(lastname);
         template.setEmailAddress(email);
         template.setDisplayName(firstname + " " + lastname);
         template.setActive(Boolean.TRUE);
         directoryManager.addUser(directory.getId(), template, new PasswordCredential(password, false));
         if (!attributes.isEmpty()) {
            directoryManager.storeUserAttributes(directory.getId(), username, attributes);
         }
         return true;
      } catch (DirectoryNotFoundException | DirectoryPermissionException | InvalidCredentialException | InvalidUserException | OperationFailedException | UserAlreadyExistsException e) {
         log.error("Error creating new user", e);
      } catch (UserNotFoundException e) {
         log.error("Error setting attributes for new user", e);
      }
      return false;
   }

   private String randomPassword() {

      //generate a random number
      String randomNum = Integer.toString(prng.nextInt());

      //get its digest
      byte[] result = sha.digest(randomNum.getBytes());
      // The byte[] returned by MessageDigest does not have a nice
      // textual representation so we Base64 encode it before returning it
      return new String(Base64.encode(result));
   }

   static String requestUriWithoutContext(HttpServletRequest request) {
      return request.getRequestURI().substring(request.getContextPath().length());
   }

   protected void doSetDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
      String application;

      if (requestToApplicationMapper != null) {
         // determine the target path
         String path;

         DefaultSavedRequest savedRequest = (DefaultSavedRequest) new HttpSessionRequestCache().getRequest(request, null);
         if (savedRequest != null) {
            path = savedRequest.getRequestURI().substring(savedRequest.getContextPath().length());
         } else {
            path = requestUriWithoutContext(request);
         }

         application = requestToApplicationMapper.getApplication(path);
      } else {
         // default to the "crowd" application
         application = clientProperties.getApplicationName();
      }

      List<ValidationFactor> validationFactors = httpTokenHelper.getValidationFactorExtractor().getValidationFactors(request);

      authRequest.setDetails(new CrowdSSOAuthenticationDetails(application, validationFactors));
   }

   /**
    * Attempts to write out the successful SSO token to a cookie, if an SSO token was generated and stored via the
    * AuthenticationProvider.
    *
    * This effectively establishes SSO when using the CrowdAuthenticationProvider in conjunction with this filter.
    *
    * @param request servlet request.
    * @param response servlet response.
    * @param chain filter chain
    * @param authResult result of a successful authentication. If it is a CrowdSSOAuthenticationToken then the SSO token
    * will be set to the "credentials" property.
    * @throws java.io.IOException not thrown.
    */
   @Override
   protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
      // write successful SSO token if there is one present
      if (authResult instanceof CrowdSSOAuthenticationToken) {
         if (authResult.getCredentials() != null) {
            try {
               httpTokenHelper.setCrowdToken(request, response, authResult.getCredentials().toString(), clientProperties, propertyManager.getCookieConfiguration());
            } catch (Exception e) {
               // occurs if application's auth token expires while trying to look up the domain property from the Crowd server
               log.error("Unable to set Crowd SSO token", e);
            }
         }
      }
      super.successfulAuthentication(request, response, chain, authResult);
   }

   /**
    * Update user attributes from request headers
    *
    * @param username
    * @param request
    * @param directory
    */
   private void updateUserAttributes(String username, HttpServletRequest request, Directory directory) {
      try {
         User foundUser = directoryManager.findUserByName(directory.getId(), username);
         UserTemplate mutableUser = new UserTemplate(foundUser);
         String firstName = request.getHeader(config.getFirstNameHeader());
         String lastName = request.getHeader(config.getLastNameHeader());
         String email = request.getHeader(config.getEmailHeader());

         if (config.isHeadersUrldecode()) {
            firstName = urlDecode(firstName);
            lastName = urlDecode(lastName);
            email = urlDecode(email);
         } else if (config.isLatin1ToUTF8()) {
            firstName = StringUtil.latin1ToUTF8(firstName);
            lastName = StringUtil.latin1ToUTF8(lastName);
         }
         if (!StringUtils.isBlank(email)) {
            mutableUser.setEmailAddress(email);
         }
         mutableUser.setFirstName(firstName);
         mutableUser.setLastName(lastName);
         mutableUser.setDisplayName(firstName + " " + lastName);
         directoryManager.updateUser(directory.getId(), mutableUser);
         Map<String, Set<String>> attributesFromHeaders = getUserAttributesFromHeaders(request);
         if (!attributesFromHeaders.isEmpty()) {
            log.debug("Storing user attributes {}", attributesFromHeaders);
            directoryManager.storeUserAttributes(directory.getId(), username, attributesFromHeaders);
         }
      } catch (UserNotFoundException e) {
         log.error("Could not find user to update attributes");
      } catch (DirectoryNotFoundException | InvalidUserException | OperationFailedException | DirectoryPermissionException e) {
         log.error("Could not update user attributes", e);
      }
   }

   private Map<String, Set<String>> getUserAttributesFromHeaders(HttpServletRequest request) {
      Map<String, Set<String>> attributesFromHeaders = new HashMap<String, Set<String>>();
      Enumeration headerValues;
      String value;
      Set<String> valueSet;
      for (String headerName : config.getAttributeHeaders()) {
         valueSet = new HashSet<String>();
         headerValues = request.getHeaders(headerName);
         while (headerValues.hasMoreElements()) {
            value = (String) headerValues.nextElement();
            if (!StringUtils.isBlank(value)) {
               valueSet.add(value);
            }
         }
         if (!valueSet.isEmpty()) {
            attributesFromHeaders.put(headerName, valueSet);
         }
      }
      return attributesFromHeaders;
   }

   private void updateUserPassword(String username, String password, Directory directory) {
      try {
         directoryManager.updateUserCredential(directory.getId(), username, new PasswordCredential(password));
      } catch (UserNotFoundException e) {
         log.error("Could not find user to update password");
      } catch (Exception e) {
         log.error("Could not update user password", e);
      }
   }

   /**
    * Update user groups according to the group mappings
    *
    * @param username
    * @param request
    * @param directory
    * @return have there changes to user groups
    */
   private boolean updateUserGroups(String username, HttpServletRequest request, Directory directory) {
      checkReloadConfig();
      boolean groupsChanged = false;
      Set<String> groupsFromHeaders = new HashSet<String>();
      Set<String> mappedGroups = new HashSet<String>();
      log.debug("Updating user groups");

      // Go through group filters
      for (GroupMapper mapper : config.getGroupMappers()) {
         mappedGroups.add(mapper.getGroup());
         if (mapper.match(request)) {
            addUserToGroup(username, mapper.getGroup(), directory);
            groupsFromHeaders.add(mapper.getGroup());
         }
      }

      // Get dynamic groups            
      if (config.getDynamicGroupHeader() != null) {
         String dynamicGroupNameString = request.getHeader(config.getDynamicGroupHeader());
         if (config.isHeadersUrldecode()) {
            dynamicGroupNameString = urlDecode(dynamicGroupNameString);
         }
         String[] dynamicGroupNames = StringUtils.split(dynamicGroupNameString, config.getDynamicGroupDelimiter());
         if (dynamicGroupNames != null) {
            for (String dynamicGroupName : dynamicGroupNames) {
               if (addUserToGroup(username, dynamicGroupName, directory)) {
                  groupsChanged = true;
               }
               groupsFromHeaders.add(dynamicGroupName);
            }
         }
      }

      // Decide which groups to purge by differencing groups from headers from
      // all the filtered groups and intersecting that with the current groups
      // of the user
      Set<String> candidatesForPurging = getCurrentGroupsForUser(username);
      if (config.getDynamicGroupPurgePrefix() != null) {
         for (String purgeCandidate : candidatesForPurging) {
            if (purgeCandidate.startsWith(config.getDynamicGroupPurgePrefix())) {
               mappedGroups.add(purgeCandidate);
            }
         }
      }
      mappedGroups.removeAll(groupsFromHeaders);
      candidatesForPurging.retainAll(mappedGroups);
      for (String groupToPurge : candidatesForPurging) {
         if (log.isDebugEnabled()) {
            log.debug("Removing user from group {}", groupToPurge);
         }
         try {
            directoryManager.removeUserFromGroup(directory.getId(), username, groupToPurge);
            groupsChanged = true;
         } catch (DirectoryPermissionException | DirectoryNotFoundException | GroupNotFoundException | MembershipNotFoundException | OperationFailedException | ReadOnlyGroupException | UserNotFoundException e) {
            log.error("Could not remove user from group {}", groupToPurge, e);
         }
      }
      return groupsChanged;
   }

   private Set<String> getCurrentGroupsForUser(String username) {
      Set<String> groups = new HashSet<>();
      try {
         MembershipQuery<GroupWithAttributes> query = QueryBuilder.createMembershipQuery(5000, 0, false, EntityDescriptor.group(), GroupWithAttributes.class, EntityDescriptor.user(), NullRestrictionImpl.INSTANCE, username);
         List<GroupWithAttributes> searchDirectGroupRelationships = applicationService.searchDirectGroupRelationships(applicationManager.findByName(clientProperties.getApplicationName()), query);
         groups.addAll(searchDirectGroupRelationships.stream().map(g -> g.getName()).collect(Collectors.toList()));
      } catch (ApplicationNotFoundException e) {
         log.error("Error getting current groups for user", e);
      }
      return groups;
   }

   /**
    * Add user to group. If group does not exist it will be created
    *
    * @param username
    * @param groupName
    * @return has user been added to group
    */
   private boolean addUserToGroup(String username, String groupName, Directory directory) {
      Group group = null;
      try {
         group = directoryManager.findGroupByName(directory.getId(), groupName);
         if (group != null && !directoryManager.isUserDirectGroupMember(directory.getId(), username, groupName)) {
            log.debug("Adding user to group {}", groupName);
            directoryManager.addUserToGroup(directory.getId(), username, groupName);
            return true;
         }
      } catch (DirectoryNotFoundException | UserNotFoundException | DirectoryPermissionException | OperationFailedException | ReadOnlyGroupException e) {
         log.error("Could not add user {} to group {}", username, groupName, e);
      } catch (GroupNotFoundException e) {
         log.debug("Could not find group {}. Will try creating it", groupName);
      } catch (MembershipAlreadyExistsException e) {
         log.error("User {} is already a member of group {}", username, groupName);
      }
      if (group == null) {
         try {
            GroupTemplate groupTemplate = new GroupTemplate(groupName, directory.getId(), GroupType.GROUP);
            groupTemplate.setActive(true);
            directoryManager.addGroup(directory.getId(), groupTemplate);
            log.debug("Group added");
            directoryManager.addUserToGroup(directory.getId(), username, groupName);
            log.debug("user added to group");
            return true;
         } catch (InvalidGroupException e) {
            log.error("Could not add group {}", groupName, e);
         } catch (GroupNotFoundException | UserNotFoundException | DirectoryNotFoundException | DirectoryPermissionException | OperationFailedException | ReadOnlyGroupException e) {
            log.error("Could not add user {} to group {}", username, groupName, e);
         } catch (MembershipAlreadyExistsException e) {
            log.error("User {} is already a member of group {}", username, groupName);
         }
      }
      return false;
   }

   /**
    * Get user details by username from the Crowd application. Can't use CrowdAuthenticationProvider as the method is
    * private so duplicating functionality
    */
   private CrowdUserDetails loadUserByUsername(String username) throws UserNotFoundException, ApplicationNotFoundException {
      User user = applicationService.findUserByName(applicationManager.findByName(clientProperties.getApplicationName()), username);
      return new CrowdUserDetails(user, Arrays.asList(findGrantedAuthorities(username)));
   }

   private GrantedAuthority[] findGrantedAuthorities(String username) throws ApplicationNotFoundException {
      return userAuthoritiesProvider.getAuthorityNames(username)
              .stream()
              .map(SimpleGrantedAuthority::new)
              .toArray(GrantedAuthority[]::new);
   }

   /**
    * Check if config needs to be reloaded
    */
   private void checkReloadConfig() {

      if (config.isReloadConfig() && config.getConfigFile() != null) {
         if (System.currentTimeMillis() < config.getConfigFileLastChecked() + config.getReloadConfigInterval()) {
            return;
         }
         
         long configFileLastModified = 0;
         try {
            configFileLastModified = Paths.get(new URI(config.getConfigFile())).toFile().lastModified();
         } catch (URISyntaxException e) {
         }
         
         log.debug("Checking config file {}, {} <> {} ", config.getConfigFile(), config.getConfigFileLastModified(), configFileLastModified);

         if (configFileLastModified != config.getConfigFileLastModified()) {
            log.debug("Config file has been changed, reloading");
            config = ConfigurationLoader.loadConfiguration();
         } else {
            log.debug("Config file has not been changed, not reloading");
            config.setConfigFileLastChecked(System.currentTimeMillis());
         }
      }
   }

   public void setClientProperties(ClientProperties clientProperties) {
      this.clientProperties = clientProperties;
   }

   public void setPropertyManager(PropertyManager propertyManager) {
      this.propertyManager = propertyManager;
   }

   public void setHttpTokenHelper(CrowdHttpTokenHelper httpTokenHelper) {
      this.httpTokenHelper = httpTokenHelper;
   }

   public void setApplicationService(ApplicationService applicationService) {
      this.applicationService = applicationService;
   }

   public void setApplicationManager(ApplicationManager applicationManager) {
      this.applicationManager = applicationManager;
   }

   public void setUserAuthoritiesProvider(UserAuthoritiesProvider userAuthoritiesProvider) {
      this.userAuthoritiesProvider = userAuthoritiesProvider;
   }

   public void setTokenAuthenticationManager(TokenAuthenticationManager tokenAuthenticationManager) {
      this.tokenAuthenticationManager = tokenAuthenticationManager;
   }

   public void setDirectoryManager(DirectoryManager directoryManager) {
      this.directoryManager = directoryManager;
   }

   /**
    * Optional dependency.
    *
    * @param requestToApplicationMapper only required if multiple Crowd "applications" need to be accessed via the same
    * Spring Security context, eg. when one web-application corresponds to multiple Crowd "applications".
    */
   public void setRequestToApplicationMapper(RequestToApplicationMapper requestToApplicationMapper) {
      this.requestToApplicationMapper = requestToApplicationMapper;
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
