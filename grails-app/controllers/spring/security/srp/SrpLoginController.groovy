package spring.security.srp

import grails.converters.JSON
import grails.plugin.springsecurity.SpringSecurityUtils
import org.springframework.security.access.annotation.Secured
import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.WebAttributes


import javax.servlet.http.HttpServletResponse

@Secured('permitAll')
class SrpLoginController {

    /** Dependency injection for the authenticationTrustResolver. */
    AuthenticationTrustResolver authenticationTrustResolver

    /** Dependency injection for the springSecurityService. */
    def springSecurityService

    def srpSecurityService

    /** Default action; redirects to 'defaultTargetUrl' if logged in, /login/auth otherwise. */
    def index() {
        if (springSecurityService.isLoggedIn()) {
            redirect uri: conf.successHandler.defaultTargetUrl
        }
        else {
            redirect action: 'auth', params: params
        }
    }

    /** Show the login page. */
    def auth() {

        def conf = getConf()

        if (springSecurityService.isLoggedIn()) {
            redirect uri: conf.successHandler.defaultTargetUrl
            return
        }

        String postUrl = request.contextPath + conf.srp.step1filterProcessesUrl
        render view: 'auth', model: [postUrl: postUrl,
                                     rememberMeParameter: conf.rememberMe.parameter,
                                     usernameParameter: conf.srp.step1UsernameParameter,
                                     gspLayout: conf.srp.gsp.layoutAuth]
    }

    //Challenge Url to get the public verifier (m1) from the server as well as user salt (s) value.
    def challenge(){
        def conf = getConf()
        String username = params.(conf.srp.step1UsernameParameter)
        String postUrl = conf.srp.step2filterProcessesUrl
        Map srpPublic

        try{

            srpPublic = srpSecurityService.step1(username)

        }catch (UsernameNotFoundException e){
            flash.message = "Username not found"
            redirect action: 'auth'
            return

        }

        if (springSecurityService.isAjax(request)) {
            render([postUrl: postUrl,
                    usernameParameter: conf.srp.step1UsernameParameter,
                    usernameValue: username,
                    saltParameter: conf.srp.step1SaltParameter,
                    userSalt: srpPublic.userSalt,
                    verifierParameter: conf.srp.step1BParameter,
                    publicVerifier: srpPublic.publicVerifier] as JSON)
            return
        }

        render view: 'validate', model: [postUrl: postUrl,
                                         usernameParameter: conf.srp.step1UsernameParameter,
                                         usernameValue: username,
                                         saltParameter: conf.srp.step1SaltParameter,
                                         userSalt: srpPublic.userSalt,
                                         verifierParameter: conf.srp.step1BParameter,
                                         publicVerifier: srpPublic.publicVerifier]
        return
    }

    /** The redirect action for Ajax requests. */
    def authAjax() {
        response.setHeader 'Location', conf.auth.ajaxLoginFormUrl
        render(status: HttpServletResponse.SC_UNAUTHORIZED, text: 'Unauthorized')
    }

    /** Show denied page. */
    def denied() {
        if (springSecurityService.isLoggedIn() && authenticationTrustResolver.isRememberMe(authentication)) {
            // have cookie but the page is guarded with IS_AUTHENTICATED_FULLY (or the equivalent expression)
            redirect action: 'full', params: params
            return
        }

        [gspLayout: conf.gsp.layoutDenied]
    }

    /** Login page for users with a remember-me cookie but accessing a IS_AUTHENTICATED_FULLY page. */
    def full() {
        def conf = getConf()
        render view: 'auth', params: params,
                model: [hasCookie: authenticationTrustResolver.isRememberMe(authentication),
                        postUrl: request.contextPath + conf.apf.filterProcessesUrl,
                        rememberMeParameter: conf.rememberMe.parameter,
                        usernameParameter: conf.apf.usernameParameter,
                        passwordParameter: conf.apf.passwordParameter,
                        gspLayout: conf.gsp.layoutAuth]
    }

    /** Callback after a failed login. Redirects to the auth page with a warning message. */
    def authfail() {

        String msg = ''
        def exception = session[WebAttributes.AUTHENTICATION_EXCEPTION]
        if (exception) {
            if (exception instanceof AccountExpiredException) {
                msg = message(code: 'springSecurity.errors.login.expired')
            }
            else if (exception instanceof CredentialsExpiredException) {
                msg = message(code: 'springSecurity.errors.login.passwordExpired')
            }
            else if (exception instanceof DisabledException) {
                msg = message(code: 'springSecurity.errors.login.disabled')
            }
            else if (exception instanceof LockedException) {
                msg = message(code: 'springSecurity.errors.login.locked')
            }
            else {
                msg = message(code: 'springSecurity.errors.login.fail')
            }
        }

        if (springSecurityService.isAjax(request)) {
            render([error: msg] as JSON)
        }
        else {
            flash.message = msg
            redirect action: 'auth', params: params
        }
    }

    /** The Ajax success redirect url. */
    def ajaxSuccess() {
        render([success: true, username: authentication.name] as JSON)
    }

    /** The Ajax denied redirect url. */
    def ajaxDenied() {
        render([error: 'access denied'] as JSON)
    }

    protected Authentication getAuthentication() {
        SecurityContextHolder.context?.authentication
    }

    protected ConfigObject getConf() {
        SpringSecurityUtils.securityConfig
    }
}
