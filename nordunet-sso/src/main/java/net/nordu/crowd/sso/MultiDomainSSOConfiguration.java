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

import com.atlassian.crowd.model.application.Application;
import com.atlassian.plugin.util.ClassLoaderUtils;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration for multiple domain sso. The configuration file
 * (MultiDomainConfiguration.properties) should contain the valid urls that can
 * be mapped to applications and the application to url map.
 * <p>The valid urls should be defined like url.&lt;id&gt;=http://foo.bar.com where
 * the id can be anything and the value is the beginning of the url where the multi 
 * domain cookie servlet will be called.
 * <p> The application maps should be defined like
 * application.&lt;applicationName&gt;=id1,foo,bar where applicationName is the
 * name of the application defined in Crowd and the value is a comma separated
 * list of url ids.
 * <p>You can control if the configuration should be reloadable with the config.reload
 * boolean setting (default false) and how often it is reloaded with config.reloadInterval
 * setting (milliseconds between possible reloads - defaults to 600000)
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class MultiDomainSSOConfiguration {

    /**
     * Map application names to urls that the application needs to call to
     * set the multidomain cookies
     */
    private static final Logger log = LoggerFactory.getLogger(MultiDomainSSOConfiguration.class);
    private final Map<String, Set<String>> applicationUrls;
    private boolean enabled;
    private boolean reloadConfig;
    private String configFile;
    private long lastReloadCheck;
    private long configFileLastModified;
    private long reloadConfigInterval;

    public MultiDomainSSOConfiguration() {
        applicationUrls = new HashMap<String, Set<String>>();
        loadConfig(false);
        lastReloadCheck = System.currentTimeMillis();
    }

    private void setConfigFileProperties() {
        URL confFileURL = ClassLoaderUtils.getResource("/MultiDomainConfiguration.properties", getClass());
        if (confFileURL != null && confFileURL.getProtocol().equals("file")) {
            configFile = confFileURL.getFile();
            configFileLastModified = new File(configFile).lastModified();
        }
    }

    private synchronized void loadConfig(boolean reload) {
        setConfigFileProperties();
        enabled = false;
        if (reload) {
            applicationUrls.clear();
        }
        if (configFile != null) {
            InputStream propsIn = null;
            Map<String, String> urls = new HashMap<String, String>();
            Map<String, Set<String>> urlMap = new HashMap<String, Set<String>>();
            try {
                propsIn = ClassLoaderUtils.getResourceAsStream("/MultiDomainConfiguration.properties", getClass());
                if (propsIn != null) {
                    Properties props = new Properties();
                    props.load(propsIn);
                    for (String key : props.stringPropertyNames()) {
                        if (key.equals("config.reload")) {
                            reloadConfig = Boolean.parseBoolean(props.getProperty(key));
                        } else if (key.equals("config.reloadInterval")) {
                            try {
                                reloadConfigInterval = Long.parseLong(props.getProperty(key));
                            } catch (NumberFormatException e) {
                                log.warn("Invalid config reload interval {}. Setting to 10 minutes (600000)", props.getProperty(key));
                                reloadConfigInterval = 600000;
                            }
                        } else if (key.contains(".")) {
                            String[] tokens = StringUtils.split(key, ".");
                            if (tokens.length > 1) {
                                if (tokens[0].equals("url")) {
                                    urls.put(tokens[1], props.getProperty(key));
                                } else if (tokens[0].equals("application")) {
                                    urlMap.put(tokens[1], new HashSet<String>(Arrays.asList(StringUtils.split(props.getProperty(key), ","))));
                                }
                            }
                        }
                    }
                    if (!urlMap.isEmpty()) {
                        for (String application : urlMap.keySet()) {
                            Set<String> urlSet = new TreeSet<String>();
                            for (String urlId : urlMap.get(application)) {
                                if (urls.containsKey(urlId)) {
                                    urlSet.add(urls.get(urlId));
                                } else {
                                    log.warn("Unknown url id {} found for application {}", urlId, application);
                                }
                            }
                            if (!urlSet.isEmpty()) {
                                applicationUrls.put(application, urlSet);
                                enabled = true;
                            }
                        }
                    }
                } else {
                    log.warn("No configuration file found for multi domain SSO. Multi domain SSO is disabled");
                }
            } catch (IOException e) {
                log.warn("Error loading configuration file found for multi domain SSO. Multi domain SSO is disabled", e);
            }
        } else {
            log.warn("No configuration file found for multi domain SSO. Multi domain SSO is disabled");
        }
    }

    public Set<String> getUrlsForApplication(String appName) {
        return applicationUrls.get(appName);
    }

    public Set<String> getUrlsForApplications(List<Application> applications) {
        Set<String> result = new TreeSet<String>();
        if (applications != null) {
            for (Application app : applications) {
                Set<String> urls = getUrlsForApplication(app.getName());
                if (urls != null) {
                    result.addAll(urls);
                }
            }
        }
        return result;
    }

    public Set<String> getApplications() {
        return applicationUrls.keySet();
    }

    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Reload configuration if necessary
     */
    public void reloadConfigIfNecessary() {
        long now = System.currentTimeMillis();        
        if (reloadConfig && configFile != null) {
            if (now < lastReloadCheck + reloadConfigInterval) {
                return;
            }
            long lastModified = new File(configFile).lastModified();            
            if (lastModified != configFileLastModified) {
                log.debug("Config file has been changed, reloading");                
                loadConfig(true);
            } else {
                log.debug("Config file has not been changed, not reloading");                
            }
            lastReloadCheck = now;
        }
    }
}
