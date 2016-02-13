/* Copyright 2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package grails.plugin.springsecurity.srp

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.web.authentication.FilterProcessUrlRequestMatcher
import grails.plugin.springsecurity.srp.authentication.SrpAuthenticationProvider
import grails.plugin.springsecurity.srp.authentication.SrpAuthenticationFilter
import grails.plugin.springsecurity.srp.userdetails.SrpGormUserDetailsService
import grails.plugins.*
import groovy.util.logging.Slf4j


/**
 * @author <a href='mailto:qusyairi@gmail.com'>Mohd Qusyairi</a>
 */

class SpringSecuritySrpGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.1.1 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

    // TODO Fill in these fields
    def title = "Spring Security Srp" // Headline display name of the plugin
    def author = "Mohd Qusyairi"
    def authorEmail = "qusyairi@gmail.com"
    def description = '''\
SRP6a Support for Spring Security plugin using Thinbus SRP.
'''
    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "http://grails.org/plugin/spring-security-srp"

    def loadAfter = ['springSecurityCore']
    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
//    def license = "APACHE"

    // Details of company behind the plugin (if there is one)
//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

    // Any additional developers beyond the author specified above.
//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

    // Location of the plugin's issue tracker.
//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

    // Online location of the plugin's browseable source code.
//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

    Closure doWithSpring() { {->

            def conf = SpringSecurityUtils.securityConfig
            if (!conf || !conf.active) {
                return
            }

            SpringSecurityUtils.loadSecondaryConfig 'DefaultSrpSecurityConfig'
            // have to get again after overlaying DefaultSrpSecurityConfig

            conf = SpringSecurityUtils.securityConfig

            if (!conf.srp.active) {
                return
            }

            boolean printStatusMessages = (conf.printStatusMessages instanceof Boolean) ? conf.printStatusMessages : true

            if (printStatusMessages) {
                println '\nConfiguring Spring Security SRP ...'
            }

            SpringSecurityUtils.registerProvider 'srpAuthProvider'
            SpringSecurityUtils.registerFilter 'srpProcessingFilter', SecurityFilterPosition.FORM_LOGIN_FILTER.order + 1

            srpAuthProvider(SrpAuthenticationProvider){
                userDetailsService = ref('userDetailsService')
                userCache = ref('userCache')
                authoritiesMapper = ref('authoritiesMapper')
                hideUserNotFoundExceptions = conf.dao.hideUserNotFoundExceptions // true
                preAuthenticationChecks = ref('preAuthenticationChecks')
                postAuthenticationChecks = ref('postAuthenticationChecks')
            }

            srpStep2ProcessUrlRequestMatcher(FilterProcessUrlRequestMatcher, conf.srp.step2filterProcessesUrl) // '/login/validatesrp'

            srpProcessingFilter(SrpAuthenticationFilter) {
                authenticationManager = ref('authenticationManager')
                sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
                authenticationSuccessHandler = ref('authenticationSuccessHandler')
                authenticationFailureHandler = ref('authenticationFailureHandler')
                rememberMeServices = ref('rememberMeServices')
                authenticationDetailsSource = ref('authenticationDetailsSource')
                requiresAuthenticationRequestMatcher = ref('srpStep2ProcessUrlRequestMatcher')
                usernameParameter = conf.srp.step1UsernameParameter // username
                aParameter = conf.srp.step2AParameter // password
                m1Parameter = conf.srp.step2M1Parameter
                continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
                allowSessionCreation = conf.apf.allowSessionCreation // true
                postOnly = conf.srp.step2postOnly // true
                storeLastUsername = conf.apf.storeLastUsername // false
            }

            /** userDetailsService */
            userDetailsService(SrpGormUserDetailsService) {
                grailsApplication = grailsApplication
            }

            srpSecurityService(SrpSecurityUtil){
                grailsApplication = grailsApplication
            }

            if (printStatusMessages) {
                println '... finished configuring Spring Security SRP\n'
            }
        }
    }

    void doWithDynamicMethods() {
        // TODO Implement registering dynamic methods to classes (optional)
    }

    void doWithApplicationContext() {
        // TODO Implement post initialization spring config (optional)
    }

    void onChange(Map<String, Object> event) {
        // TODO Implement code that is executed when any artefact that this plugin is
        // watching is modified and reloaded. The event contains: event.source,
        // event.application, event.manager, event.ctx, and event.plugin.
    }

    void onConfigChange(Map<String, Object> event) {
        // TODO Implement code that is executed when the project configuration changes.
        // The event is the same as for 'onChange'.
    }

    void onShutdown(Map<String, Object> event) {
        // TODO Implement code that is executed when the application shuts down (optional)
    }
}
