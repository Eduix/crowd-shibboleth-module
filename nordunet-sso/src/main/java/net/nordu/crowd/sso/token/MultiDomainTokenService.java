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
package net.nordu.crowd.sso.token;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * Simple service to handle generating and validating single use tokens
 * for identifying the sso cookie for multi domain sso
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 * @version $Id$
 */
public class MultiDomainTokenService {

    private static final Logger log = Logger.getLogger(MultiDomainTokenService.class);
    public static final long MAX_TTL = 1000 * 10;
    private final Map<String, Token> tokenStore;
    private final SecureRandom prng;

    public MultiDomainTokenService() {
        tokenStore = Collections.synchronizedMap(new HashMap<String, Token>(200));
        try {
            prng = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not instantiate SHA1PRNG for multi domain token service");
        }
    }

    public String createToken(String cookieToken) {
        String uid = generateUID();
        while (tokenStore.containsKey(uid)) {
            uid = generateUID();
        }
        tokenStore.put(uid, new Token(uid, cookieToken));
        return uid;
    }

    /**
     * Consume token and return it.
     * @param id
     * @return
     * @throws InvalidTokenException if no token is found or token is too old
     */
    public Token consumeToken(String id) throws InvalidTokenException {
        Token token = tokenStore.remove(id);
        if (token == null) {
            throw new InvalidTokenException("No token with id " + id);
        } else if (!token.isValid()) {
            throw new InvalidTokenException("Token " + id + " is too old");
        }
        return token;
    }

    private String generateUID() {
        String uid = Integer.toHexString(prng.nextInt());
        if (uid.length() > 16) {
            return StringUtils.right(uid, 16);
        }
        return uid;
    }
}
