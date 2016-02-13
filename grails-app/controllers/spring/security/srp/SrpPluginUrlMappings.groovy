package spring.security.srp

import grails.plugin.springsecurity.SpringSecurityUtils

class SrpPluginUrlMappings {

    static mappings = {
        //Change default spring security core
        def conf = SpringSecurityUtils.securityConfig
        if(conf.srp.srpAsDefaultLoginFormUrl){
            "/login/auth"(controller: "srpLoginController", action: "auth")
        }
    }
}
