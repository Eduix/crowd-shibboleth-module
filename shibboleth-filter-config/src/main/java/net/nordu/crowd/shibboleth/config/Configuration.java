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
package net.nordu.crowd.shibboleth.config;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * Model for configuration
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class Configuration {

   private Set<GroupMapper> groupMappers;   
   private String dynamicGroupHeader;
   private String dynamicGroupDelimiter;
   private String dynamicGroupPurgePrefix;   
   private boolean reloadConfig;
   private long reloadConfigInterval;
   private String configFile;
   private long configFileLastModified;
   private long configFileLastChecked;
   private boolean createUser;
   private String directoryName;
   private boolean latin1ToUTF8;
   private boolean headersUrldecode;
   private String firstNameHeader;
   private String lastNameHeader;
   private String emailHeader;
   private Set<String> homeOrganizations;
   private Map<String, String> applicationMap;   
   private boolean syncEveryLogin;
   private Set<String> attributeHeaders;

   private boolean enableUserAccounts;
   private boolean createUsersDisabled;

   public String getEmailHeader() {
      return emailHeader;
   }

   public void setEmailHeader(String emailHeader) {
      this.emailHeader = emailHeader;
   }

   public String getFirstNameHeader() {
      return firstNameHeader;
   }

   public void setFirstNameHeader(String firstNameHeader) {
      this.firstNameHeader = firstNameHeader;
   }

   public String getLastNameHeader() {
      return lastNameHeader;
   }

   public void setLastNameHeader(String lastNameHeader) {
      this.lastNameHeader = lastNameHeader;
   }

   public Set<GroupMapper> getGroupMappers() {
      return groupMappers;
   }

   public void setGroupMappers(Set<GroupMapper> groupMappers) {
      this.groupMappers = groupMappers;
   }   

   public String getDynamicGroupHeader() {
      return dynamicGroupHeader;
   }

   public void setDynamicGroupHeader(String dynamicGroupHeader) {
      this.dynamicGroupHeader = dynamicGroupHeader;
   }

   public String getDynamicGroupDelimiter() {
      return dynamicGroupDelimiter;
   }

   public void setDynamicGroupDelimiter(String dynamicGroupDelimiter) {
      this.dynamicGroupDelimiter = dynamicGroupDelimiter;
   }

   public String getDynamicGroupPurgePrefix() {
      return dynamicGroupPurgePrefix;
   }

   public void setDynamicGroupPurgePrefix(String dynamicGroupPurgePrefix) {
      this.dynamicGroupPurgePrefix = dynamicGroupPurgePrefix;
   }   

   public boolean isReloadConfig() {
      return reloadConfig;
   }

   public void setReloadConfig(boolean reloadConfig) {
      this.reloadConfig = reloadConfig;
   }

   public long getReloadConfigInterval() {
      return reloadConfigInterval;
   }

   public void setReloadConfigInterval(long reloadConfigInterval) {
      this.reloadConfigInterval = reloadConfigInterval;
   }

   public long getConfigFileLastChecked() {
      return configFileLastChecked;
   }

   public void setConfigFileLastChecked(long configFileLastChecked) {
      this.configFileLastChecked = configFileLastChecked;
   }

   public long getConfigFileLastModified() {
      return configFileLastModified;
   }

   public void setConfigFileLastModified(long configFileLastModified) {
      this.configFileLastModified = configFileLastModified;
   }

   public String getConfigFile() {
      return configFile;
   }

   public void setConfigFile(String configFile) {
      this.configFile = configFile;
   }

   public String getDirectoryName() {
      return directoryName;
   }   

   public void setDirectoryName(String directoryName) {
      this.directoryName = directoryName;
   }

   public boolean isCreateUser() {
      return createUser;
   }

   public void setCreateUser(boolean createUser) {
      this.createUser = createUser;
   }

   public Set<String> getHomeOrganizations() {
      return homeOrganizations;
   }

   public void setHomeOrganizations(Set<String> homeOrganizations) {
      this.homeOrganizations = homeOrganizations;
   }

   public boolean isLatin1ToUTF8() {
      return latin1ToUTF8;
   }

   public void setLatin1ToUTF8(boolean latin1ToUTF8) {
      this.latin1ToUTF8 = latin1ToUTF8;
   }

   public boolean isHeadersUrldecode() {
      return headersUrldecode;
   }

   public void setHeadersUrldecode(boolean headersUrldecode) {
      this.headersUrldecode = headersUrldecode;
   }

   public void setApplicationMap(Map<String, String> applicationMap) {
      this.applicationMap = applicationMap;
   }

   public String getUrl(String application) {
      return application == null ? null : applicationMap.get(application);
   }

   public Collection<String> getAllUrls() {
      return Collections.unmodifiableCollection(applicationMap.values());
   }

   public boolean syncRequired() {
      return !applicationMap.isEmpty();
   }

   public Set<String> getAttributeHeaders() {
      return attributeHeaders;
   }

   public void setAttributeHeaders(Set<String> attributeHeaders) {
      this.attributeHeaders = attributeHeaders;
   }

   public boolean isSyncEveryLogin() {
      return syncEveryLogin;
   }

   public void setSyncEveryLogin(boolean syncEveryLogin) {
      this.syncEveryLogin = syncEveryLogin;
   }

   public boolean isEnableUserAccounts() {
      return enableUserAccounts;
   }

   public void setEnableUserAccounts(boolean enableUserAccounts) {
      this.enableUserAccounts = enableUserAccounts;
   }

   public boolean isCreateUsersDisabled() {
      return createUsersDisabled;
   }

   public void setCreateUsersDisabled(boolean createUsersDisabled) {
      this.createUsersDisabled = createUsersDisabled;
   }

   public static Configuration newInstanceFromFile() {
      return ConfigurationLoader.loadConfiguration();
   }
}
