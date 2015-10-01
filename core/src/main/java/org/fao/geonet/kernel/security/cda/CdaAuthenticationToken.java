package org.fao.geonet.kernel.security.cda;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;

import java.util.Collection;

/**
 * Created by Vincent Valot on 30/09/2015.
 */
public class CdaAuthenticationToken extends UsernamePasswordAuthenticationToken {

    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

    private Object key;

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>UsernamePasswordAuthenticationToken</code>, as the {@link
     * #isAuthenticated()} will return <code>false</code>.
     *
     */
    public CdaAuthenticationToken(Object principal, Object credentials, Object key) {
        super(principal, credentials);

        this.key = key;
    }

    public Object getKey() {
        return this.key;
    }
}
