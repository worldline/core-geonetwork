package org.fao.geonet.kernel.security.cda;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by a614803 on 30/09/2015.
 */
public class CdaUserAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String SPRING_SECURITY_FORM_ACCESS_KEY = "j_jey";

    private String keyParameter = SPRING_SECURITY_FORM_ACCESS_KEY;

    private boolean postOnly = true;

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = obtainUsername(request);
        String password = obtainPassword(request);
        String key = obtainKey(request);

        if (username == null) {
            username = "";
        }

        if (password == null) {
            password = "";
        }

        if (key == null) {
            password = "";
        }

        username = username.trim();

        CdaAuthenticationToken authRequest = new CdaAuthenticationToken(username, password, key);

        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);

        return this.getAuthenticationManager().authenticate(authRequest);
    }

    /**
     * Enables subclasses to override the composition of the key, such as by including additional values
     * and a separator.<p>This might be used for example if a postcode/zipcode was required in addition to the
     * password. A delimiter such as a pipe (|) should be used to separate the password and extended value(s). The
     * <code>AuthenticationDao</code> will need to generate the expected password in a corresponding manner.</p>
     *
     * @param request so that request attributes can be retrieved
     *
     * @return the key that will be presented in the <code>Authentication</code> request token to the
     *         <code>AuthenticationManager</code>
     */
    protected String obtainKey(HttpServletRequest request) {
        return request.getParameter(this.keyParameter);
    }

    /**
     * Sets the parameter name which will be used to obtain the key from the login request..
     *
     * @param keyParameter the parameter name. Defaults to "j_password".
     */
    public void setKeyParameter(String keyParameter) {
        Assert.hasText(keyParameter, "Access key must not be empty or null");
        this.keyParameter = keyParameter;
    }

    public final String getKeyParameter() {
        return this.keyParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }
}
