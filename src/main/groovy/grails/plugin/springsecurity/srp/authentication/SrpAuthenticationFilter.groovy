/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package grails.plugin.springsecurity.srp.authentication

import groovyjarjarantlr.collections.List;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession

/**
 * Processes an authentication form submission. Called
 * {@code AuthenticationProcessingFilter} prior to Spring Security 3.0.
 * <p>
 * Login forms must present two parameters to this filter: a username and password. The
 * default parameter names to use are contained in the static fields
 * {@link #SPRING_SECURITY_FORM_USERNAME_KEY} and
 * {@link #SPRING_SECURITY_FORM_PASSWORD_KEY}. The parameter names can also be changed by
 * setting the {@code usernameParameter} and {@code passwordParameter} properties.
 * <p>
 * This filter by default responds to the URL {@code /login}.
 *
 * @author Ben Alex
 * @author Colin Sampaleanu
 * @author Luke Taylor
 * @since 3.0
 */

public class SrpAuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {
	// ~ Static fields/initializers
	// =====================================================================================

	public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "j_username";
	public static final String SPRING_SECURITY_FORM_A_KEY = "j_a";
	public static final String SPRING_SECURITY_FORM_M1_KEY = "j_m1";

	private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
	private String aParameter = SPRING_SECURITY_FORM_A_KEY;
	private String m1Parameter = SPRING_SECURITY_FORM_M1_KEY;
	private boolean postOnly = true;
	/** Whether to store the last attempted username in the session. */
	private Boolean storeLastUsername

	// ~ Constructors
	// ===================================================================================================

	public SrpAuthenticationFilter() {
		super(new AntPathRequestMatcher("/srp_login", "POST"));
	}

	// ~ Methods
	// ========================================================================================================

	public Authentication attemptAuthentication(HttpServletRequest request,
			HttpServletResponse response) throws AuthenticationException {
		if (postOnly && !request.getMethod().equals("POST")) {
			throw new AuthenticationServiceException(
					"Authentication method not supported: " + request.getMethod());
		}

		String username = obtainUsername(request);
		Map srpStep2Credential = obtainSrpStep2(request);

		if (username == null) {
			username = "";
		}

		if (srpStep2Credential.a == null) {
			srpStep2Credential.a = "";
		}

        if (srpStep2Credential.m1 == null) {
            srpStep2Credential.m1 = "";
        }

		username = username.trim();

		UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(
				username, srpStep2Credential);

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

        if (storeLastUsername) {
            // Place the last username attempted into HttpSession for views
            HttpSession session = request.getSession(false)
            if (!session && allowSessionCreation) {
                session = request.session
            }

            session?.setAttribute SpringSecurityUtils.SPRING_SECURITY_LAST_USERNAME_KEY, (obtainUsername(request) ?: '').trim()
        }


        return this.getAuthenticationManager().authenticate(authRequest);
	}

	/**
	 * Enables subclasses to override the composition of the password, such as by
	 * including additional values and a separator.
	 * <p>
	 * This might be used for example if a postcode/zipcode was required in addition to
	 * the password. A delimiter such as a pipe (|) should be used to separate the
	 * password and extended value(s). The <code>AuthenticationDao</code> will need to
	 * generate the expected password in a corresponding manner.
	 * </p>
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the password that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected Map obtainSrpStep2(HttpServletRequest request) {
        Map srpStep2 = [:]
        srpStep2['a'] = request.getParameter(aParameter)
        srpStep2['m1'] = request.getParameter(m1Parameter)
		return srpStep2
	}

	/**
	 * Enables subclasses to override the composition of the username, such as by
	 * including additional values and a separator.
	 *
	 * @param request so that request attributes can be retrieved
	 *
	 * @return the username that will be presented in the <code>Authentication</code>
	 * request token to the <code>AuthenticationManager</code>
	 */
	protected String obtainUsername(HttpServletRequest request) {
		return request.getParameter(usernameParameter);
	}

	/**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			UsernamePasswordAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Sets the parameter name which will be used to obtain the username from the login
	 * request.
	 *
	 * @param usernameParameter the parameter name. Defaults to "username".
	 */
	public void setUsernameParameter(String usernameParameter) {
		Assert.hasText(usernameParameter, "Username parameter must not be empty or null");
		this.usernameParameter = usernameParameter;
	}

	/**
	 * Sets the parameter name which will be used to obtain the password from the login
	 * request..
	 *
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setM1Parameter(String m1Parameter) {
		Assert.hasText(m1Parameter, "Password parameter must not be empty or null");
		this.m1Parameter = m1Parameter;
	}

	/**
	 * Sets the parameter name which will be used to obtain the password from the login
	 * request..
	 *
	 * @param passwordParameter the parameter name. Defaults to "password".
	 */
	public void setAParameter(String aParameter) {
		Assert.hasText(aParameter, "Password parameter must not be empty or null");
		this.aParameter = aParameter;
	}

	/**
	 * Defines whether only HTTP POST requests will be allowed by this filter. If set to
	 * true, and an authentication request is received which is not a POST request, an
	 * exception will be raised immediately and authentication will not be attempted. The
	 * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
	 * authentication.
	 * <p>
	 * Defaults to <tt>true</tt> but may be overridden by subclasses.
	 */
	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

    public void setStoreLastUsername(boolean storeLastUsername) {
        this.storeLastUsername = storeLastUsername;
    }

	public final String getUsernameParameter() {
		return usernameParameter;
	}

	public final String getM1Parameter() {
		return m1Parameter;
	}

	public final String getAParameter() {
		return aParameter;
	}
}