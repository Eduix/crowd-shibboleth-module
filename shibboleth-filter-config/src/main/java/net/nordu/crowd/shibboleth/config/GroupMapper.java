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

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;

/**
 * Class for mapping groups for users based on HttpServletRequest headers
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class GroupMapper {
    private static final Logger log = Logger.getLogger(GroupMapper.class);
    private String group;
    private Map<String, String> headerMatches;
    // do all the header matches have to pass or just any one of them
    private boolean exclusive = true;
    private boolean caseSensitive = true;

    public GroupMapper(String group, Map<String, String> headerMatches) {
        this.group = group;
        this.headerMatches = headerMatches;
    }

    public GroupMapper(String group, Map<String, String> headerMatches, boolean exclusive, boolean caseSensitive) {
        this.group = group;
        this.headerMatches = headerMatches;
        this.exclusive = exclusive;
        this.caseSensitive = caseSensitive;
    }

    public String getGroup() {
        return group;
    }

    public void setGroup(String group) {
        this.group = group;
    }

    public Map<String, String> getHeaderMatches() {
        return headerMatches;
    }

    public void setHeaderMatches(Map<String, String> headerMatches) {
        this.headerMatches = headerMatches;
    }

    public boolean isExclusive() {
        return exclusive;
    }

    public void setExclusive(boolean exclusive) {
        this.exclusive = exclusive;
    }

    public boolean isCaseSensitive() {
        return caseSensitive;
    }

    public void setCaseSensitive(boolean caseSensitive) {
        this.caseSensitive = caseSensitive;
    }


    public boolean match(final HttpServletRequest req) {
        boolean match = false;
        for (String header : headerMatches.keySet()) {
            Pattern pattern  = null;
            if(caseSensitive) {
                pattern = Pattern.compile(headerMatches.get(header));
            } else {
                pattern = Pattern.compile(headerMatches.get(header), Pattern.CASE_INSENSITIVE);
            }
            String val = req.getHeader(header);
            if(val==null) {
                val="";
            }
            Matcher m = pattern.matcher(val);
            if(m.find()) {
                log.debug("Pattern "+headerMatches.get(header)+" found in header "+ header + " value "+val);
                if(!exclusive) {
                    return true;
                } else {
                    match = true;
                }
            } else {
                log.debug("Pattern "+headerMatches.get(header)+" not found in header "+ header + " value "+val);
                if(exclusive) {
                    return false;
                }
            }
        }
        return match;
    }
}
