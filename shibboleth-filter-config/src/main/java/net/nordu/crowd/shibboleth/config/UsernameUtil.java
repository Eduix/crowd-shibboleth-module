/*
 * Copyright (c) 2012 Eduix Oy
 * All rights reserved
 */
package net.nordu.crowd.shibboleth.config;

/**
 * Utility to strip domain suffixes from usernames if necessary
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class UsernameUtil {

    public static String getFinalUsername(String remoteUserHeader, Configuration config) {
        if (remoteUserHeader != null && remoteUserHeader.indexOf('@') != -1 && config.getHomeOrganizations() != null && !config.getHomeOrganizations().isEmpty()) {
            for (String org : config.getHomeOrganizations()) {
                if (remoteUserHeader.endsWith('@' + org)) {
                    return remoteUserHeader.substring(0, remoteUserHeader.length()-org.length()-1);
                }
            }
        }
        return remoteUserHeader;
    }
}
