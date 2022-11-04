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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.atlassian.plugin.util.ClassLoaderUtils;

/**
 * Class for loading filter configuration
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class ConfigurationLoader {

   private static final Logger log = LoggerFactory.getLogger(ConfigurationLoader.class);

   public static Configuration loadConfiguration() {
        Configuration config = new Configuration();
        try {
            Map<String, GroupMapper> mappings = new HashMap<String, GroupMapper>();
            Set<String> attributes = new HashSet<String>();
            Set<String> groupsToPurge = new HashSet<String>();
            
            String configFilePath = System.getenv(Constants.CONFIG_FILE_ENV_NAME);
            InputStream propsIn = null;
            if (configFilePath != null) {
               try {
                  File configFile = Paths.get(new URI(configFilePath)).toFile();
                  propsIn = new FileInputStream(configFile);
               } catch (URISyntaxException | IOException e) {
                  throw new RuntimeException("Error loading configuration properties from file " + configFilePath, e);
               }
            }
            if (propsIn == null) {
               propsIn = ClassLoaderUtils.getResourceAsStream(Constants.CONFIG_FILE, ConfigurationLoader.class);
               if (propsIn == null) {
                  throw new RuntimeException("Error loading configuration properties. Configuration file not found (\""
                           + Constants.CONFIG_FILE + "\")");
               }
               URL confFileURL = ClassLoaderUtils.getResource(Constants.CONFIG_FILE, ConfigurationLoader.class);
               if (confFileURL != null && confFileURL.getProtocol().equals("file")) {
                  configFilePath = confFileURL.getFile();
               }
            }
            Properties props = new Properties();

            props.load(propsIn);

            config.setReloadConfig(Boolean.parseBoolean(props.getProperty(Constants.RELOAD_CONFIG)));
            String reloadInterval = props.getProperty(Constants.RELOAD_CONFIG_INTERVAL);
            if (reloadInterval != null) {
                try {
                    config.setReloadConfigInterval(Long.parseLong(reloadInterval) * 1000);
                } catch (NumberFormatException e) {
                    config.setReloadConfigInterval(3600 * 1000);
                }
            }
            config.setConfigFileLastChecked(System.currentTimeMillis());
            //URL confFileURL = ClassLoaderUtils.getResource(Constants.CONFIG_FILE, ConfigurationLoader.class);
            //if (confFileURL != null && confFileURL.getProtocol().equals("file")) {
            //    String confFile = confFileURL.getFile();
               config.setConfigFile(configFilePath);
               long configFileLastModified;
               try {
                  configFileLastModified = Paths.get(new URI(configFilePath)).toFile().lastModified();
                  config.setConfigFileLastModified(configFileLastModified);
               } catch (URISyntaxException e) {
               }
            //}


            // Load group mappings
            Map<String, GroupMapper> mappers = new HashMap<String, GroupMapper>();
            for (Object key : props.keySet()) {
                String keyString = (String) key;
                if (keyString.contains(Constants.DELIMITER)) {
                    String[] parts = keyString.split(Constants.DELIMITER_REGEX, 0);
                    handleGroupMapperParts(parts, mappers, props.getProperty(keyString));
                }
            }

            Set<GroupMapper> groupMappers = new HashSet<GroupMapper>();
            for (GroupMapper mapper : mappers.values()) {
                if (!mapper.getHeaderMatches().isEmpty()) {
                    groupMappers.add(mapper);
                }
            }
            config.setGroupMappers(groupMappers);
            log.debug("Group filters: " + groupMappers.size());

            // Dynamic group mapping
            config.setDynamicGroupHeader(props.getProperty(Constants.DYNAMIC_GROUP_HEADER));
            config.setDynamicGroupDelimiter(props.getProperty(Constants.DYNAMIC_GROUP_DELIMITER, ";"));
            config.setDynamicGroupPurgePrefix(props.getProperty(Constants.DYNAMIC_GROUP_PURGE_PREFIX));
            
            config.setCreateUser(Boolean.parseBoolean(props.getProperty(Constants.CREATE_USER, "true")));
            
            if (props.getProperty(Constants.DIRECTORY_NAME) != null) {
                config.setDirectoryName(props.getProperty(Constants.DIRECTORY_NAME));
            } else {
                throw new RuntimeException("User directory name must be specified");
            }

            config.setLatin1ToUTF8(Boolean.parseBoolean(props.getProperty(Constants.LATIN1_TO_UTF8, "true")));
            config.setHeadersUrldecode(Boolean.parseBoolean(props.getProperty(Constants.HEADERS_URLDECODE, "false")));

            config.setFirstNameHeader(props.getProperty(Constants.HEADER_FIRST_NAME, "givenName"));
            config.setLastNameHeader(props.getProperty(Constants.HEADER_LAST_NAME, "sn"));
            config.setEmailHeader(props.getProperty(Constants.HEADER_MAIL, "mail"));

            Map<String, String> applicationMap = new HashMap<String, String>();
            for (Object key : props.keySet()) {
                String k = (String) key;
                if(k.startsWith(Constants.SYNC) && StringUtils.split(k, '.').length == 2) {
                    String appName = k.substring(5);
                    applicationMap.put(appName, props.getProperty(k));
                }
            }
            config.setApplicationMap(applicationMap);

            config.setSyncEveryLogin(Boolean.parseBoolean(props.getProperty(Constants.SYNC_EVERY_LOGIN, "false")));
            
            String homeOrganizationsStr = props.getProperty(Constants.HOME_ORGANIZATIONS);
            if(homeOrganizationsStr != null) {
                Set homeOrgs = new HashSet<String>();
                for(String org: StringUtils.split(homeOrganizationsStr, ",")) {
                    homeOrgs.add(org.trim());
                }
                config.setHomeOrganizations(homeOrgs);
            }
            
            String attributeHeaderStr = props.getProperty(Constants.ATTRIBUTE_HEADERS);
            if(attributeHeaderStr != null) {
               Set attributeHeaders = new HashSet<String>();
               for (String header : StringUtils.split(attributeHeaderStr, ",")) {
                  attributeHeaders.add(header.trim());
               }
               config.setAttributeHeaders(attributeHeaders);
            } else {
               config.setAttributeHeaders(Collections.EMPTY_SET);
            }

        } catch (IOException ex) {
            log.error("Error loading configuration properties", ex);
        }
        return config;
    }

   private static File getConfigFile() {
      try {
         String configFilePath = System.getenv(Constants.CONFIG_FILE_ENV_NAME);
         if (configFilePath == null) {
            return null;
         }
         File configFile = Paths.get(new URI(configFilePath)).toFile();
         if (configFile.isFile()) {
            return configFile;
         }
      } catch (URISyntaxException e) {
      }
      return null;
   }

   private static void handleGroupMapperParts(String[] parts, Map<String, GroupMapper> mappers, String val) {
      if (parts.length >= 3 && Constants.GROUP.equals(parts[0])) {
         String group = parts[1];
         GroupMapper filter = mappers.get(group);
         if (filter == null) {
            filter = new GroupMapper(group, new HashMap<String, String>());
            mappers.put(group, filter);
         }
         if (Constants.GROUP_MAPPER_SENSITIVE.equals(parts[2])) {
            filter.setCaseSensitive(Boolean.parseBoolean(val));
         } else if (Constants.GROUP_MAPPER_EXCLUSIVE.equals(parts[2])) {
            filter.setExclusive(Boolean.parseBoolean(val));
         } else if (Constants.GROUP_MAPPER_MATCH.equals(parts[2]) && parts.length == 4) {
            filter.getHeaderMatches().put(parts[3], val);
         }
      }
   }
}
