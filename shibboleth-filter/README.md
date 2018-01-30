# What is this?

The Shibboleth filter is an authentication processing filter which is used to authenticate and populate users in Crowd
using the HTTP headers set by Shibboleth.

# Installation

To install the Shibboleth filter to crowd copy the created jar file to %crowd-webapp%/WEB-INF/lib
and modify %crowd-webapp%/WEB-INF/classes/applicationContext-CrowdSecurity.xml.

Add the custom filter to the chain like this:
    <security:http auto-config="false"
          authentication-manager-ref="authenticationManager"
          entry-point-ref="crowdAuthenticationProcessingFilterEntryPoint"
          access-denied-page="/console/accessdenied.action" >
        <security:custom-filter position="FORM_LOGIN_FILTER" ref='authenticationProcessingFilter'/>
        <security:custom-filter after="FORM_LOGIN_FILTER" ref='authenticationProcessingShibbolethFilter'/>
        <security:custom-filter position="LOGOUT_FILTER" ref='logoutFilter'/>

        <security:intercept-url pattern="/console/secure/**" access="ROLE_ADMIN"/>
        <security:intercept-url pattern="/console/user/**" access="IS_AUTHENTICATED_FULLY"/>
        <security:intercept-url pattern="/console/plugin/secure/**" access="IS_AUTHENTICATED_FULLY"/>
    </security:http>

Then add this bean definition after the authenticationProcessingFilter bean:

    <bean id="authenticationProcessingShibbolethFilter" class="net.nordu.crowd.shibboleth.ShibbolethSSOFilter">
        <property name="clientProperties" ref="clientProperties"/>
        <property name="propertyManager" ref="propertyManager"/>
        <property name="httpTokenHelper" ref="httpTokenHelper"/>
        <property name="tokenAuthenticationManager" ref="tokenAuthenticationManager"/>
        <property name="authenticationManager" ref="authenticationManager"/>
        <property name="applicationService" ref="applicationService"/>
        <property name="applicationManager" ref="applicationManager"/>
        <property name="userAuthoritiesProvider" ref="userAuthoritiesProvider"/>
        <property name="filterProcessesUrl" value="/console/j_security_check"/>
        <property name="directoryManager" ref="directoryManager"/>
        <property name="authenticationFailureHandler">
            <bean class="com.atlassian.crowd.integration.springsecurity.UsernameStoringAuthenticationFailureHandler">
                <constructor-arg>
                    <util:constant static-field="com.atlassian.crowd.integration.springsecurity.SecurityConstants.USERNAME_PARAMETER"/>
                </constructor-arg>
                <property name="defaultFailureUrl" value="/console/login.action?error=true"/>
            </bean>
        </property>
         
        <property name="authenticationSuccessHandler">
            <bean class="net.nordu.crowd.shibboleth.SavedRequestAwarePassThroughAuthenticationSuccessHandler" />
        </property>
        <property name="requestToApplicationMapper" ref="requestToApplicationMapper"/>
    </bean>

Finally you need to create a ShibbolethSSOFilter.properties file in %crowd-webapp%/WEB-INF/classes. There is an example file under src/main/resources/
