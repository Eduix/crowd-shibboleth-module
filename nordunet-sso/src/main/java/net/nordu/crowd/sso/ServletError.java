/*
 * Copyright (c) 2017 Eduix Oy
 * All rights reserved
 */
package net.nordu.crowd.sso;

/**
 *
 * @author Juha-Matti Leppälä <juha@eduix.fi>
 */
public enum ServletError {

   NOT_PERMITTED("<p>You are not permitted to use the requested service</p>", "notPermitted.html");

   private ServletError(String defaultContent, String fragment) {
      this.defaultContent = defaultContent;
      this.fragment = fragment;
   }

   private String defaultContent;
   private String fragment;

   public String getDefaultContent() {
      return defaultContent;
   }

   public String getFragment() {
      return fragment;
   }

}
