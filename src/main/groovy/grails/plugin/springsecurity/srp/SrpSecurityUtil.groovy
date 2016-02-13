package grails.plugin.springsecurity.srp

/**
 * Created by Mohd Qusyairi on 13/2/2016.
 */
import grails.core.GrailsApplication
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import com.bitbucket.thinbus.srp6.js.SRP6JavascriptServerSessionSHA256
import com.bitbucket.thinbus.srp6.js.SRP6JavascriptServerSession
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.web.context.request.RequestContextHolder as RCH
import grails.plugin.springsecurity.SpringSecurityUtils

class SrpSecurityUtil {
    protected Logger log = LoggerFactory.getLogger(getClass())

    /** Dependency injection for the application. */
    GrailsApplication grailsApplication


    def step1(username){

        def conf = SpringSecurityUtils.securityConfig
        String N = conf.srp.cryptoParams.N_base10
        String g = conf.srp.cryptoParams.g_base10
        def session = RCH.currentRequestAttributes().session
        SRP6JavascriptServerSession serverSession = new SRP6JavascriptServerSessionSHA256(N,g);

        String userClassName = conf.userLookup.userDomainClassName
        def dc = grailsApplication.getDomainClass(userClassName)
        if (!dc) {
            throw new IllegalArgumentException("The specified user domain class '$userClassName' is not a domain class")
        }

        Class<?> User = dc.clazz

        def userToVerified = User.findWhere((conf.userLookup.usernamePropertyName): username)

        if (!userToVerified) {
            log.warn 'User not found: {}', username
            throw new UsernameNotFoundException('No Username found')
        }


        // Compute the public server value 'B'
        serverSession.step1(userToVerified.username, userToVerified.(conf.srp.userLookup.saltPropertyName), userToVerified.(conf.srp.userLookup.verifierPropertyName));
        // Hold it to session
        session[conf.srp.sessionKey] = serverSession
        String publicB = serverSession.getPublicServerValue()
        String publicS = userToVerified.(conf.srp.userLookup.saltPropertyName)
        return [userSalt:publicS,publicVerifier:publicB]
    }
}
