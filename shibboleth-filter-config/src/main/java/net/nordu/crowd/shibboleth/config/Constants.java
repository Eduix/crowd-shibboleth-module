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

/**
 * Constants
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
interface Constants {

    public static final String CONFIG_FILE_ENV_NAME = "SHIBBOLETH_FILTER_CONFIG";
    public static final String CONFIG_FILE = "/ShibbolethSSOFilter.properties";
    public static final String DELIMITER = ".";
    public static final String DELIMITER_REGEX = "\\.";
    public static final String GROUP = "group";
    public static final String GROUP_PRE = GROUP + DELIMITER;
    public static final String GROUP_MAPPER_MATCH = "match";
    public static final String GROUP_MAPPER_SENSITIVE = "sensitive";    
    public static final String GROUP_MAPPER_EXCLUSIVE = "exclusive";
    public static final String DYNAMIC_GROUP_HEADER = "dynamic.group.header";
    public static final String DYNAMIC_GROUP_DELIMITER = "dynamic.group.delimiter";
    public static final String DYNAMIC_GROUP_PURGE_PREFIX = "dynamic.group.purge.prefix";
    public static final String RELOAD_CONFIG = "reload.config";
    public static final String RELOAD_CONFIG_INTERVAL = "reload.config.interval";
    public static final String CREATE_USER = "create.user";
    public static final String DIRECTORY_NAME = "directory.name";
    public static final String LATIN1_TO_UTF8 = "headers.latin1toutf8";
    public static final String HEADERS_URLDECODE = "headers.urldecode";
    public static final String HEADER_FIRST_NAME = "headers.firstname";
    public static final String HEADER_LAST_NAME = "headers.lastname";
    public static final String HEADER_MAIL = "headers.mail";
    public static final String SYNC = "sync";
    public static final String SYNC_EVERY_LOGIN = "sync.every.login";
    public static final String HOME_ORGANIZATIONS = "home.organizations";
    public static final String ATTRIBUTE_HEADERS = "headers.to.attributes";
}
