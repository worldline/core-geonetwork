package org.fao.geonet.kernel.security.cda;

import junit.framework.TestCase;
import org.fao.geonet.AbstractCoreIntegrationTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.ContextConfiguration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ContextConfiguration(inheritLocations = true, locations = "classpath:cda-test-context.xml")
public class CdaAuthenticationProviderTest extends AbstractCoreIntegrationTest {

    public static final String USERNAME = "atos";
    public static final String PASSWORD = "atos";
    public static final String KEY = "atos01234567890123456789";

    @Autowired
    private CdaAuthenticationProvider _cdaAuthenticationProvider;
    @Autowired
    private ApplicationContext _appContext;

    private CdaAuthenticationToken authentication;

    @Test
    public void testAuthenticationShouldBeSuccessful() throws Exception{
        this.authentication = mock(CdaAuthenticationToken.class);

        when(authentication.getName()).thenReturn(USERNAME);
        when(authentication.getCredentials()).thenReturn(PASSWORD);
        when(authentication.getKey()).thenReturn(KEY);

        final UserDetails userDetails = _cdaAuthenticationProvider.retrieveUser("atos", authentication);
        TestCase.assertNotNull("User with authentication token should be found", userDetails);
    }

    @Test (expected = AuthenticationServiceException.class)
    public void testAuthenticationWrongCredentials() throws Exception{
        this.authentication = mock(CdaAuthenticationToken.class);

        when(authentication.getName()).thenReturn("abracadabra");
        when(authentication.getCredentials()).thenReturn("abracadabra");
        when(authentication.getKey()).thenReturn(KEY);

        _cdaAuthenticationProvider.retrieveUser("atos", authentication);
    }

    @Test (expected = AuthenticationServiceException.class)
    public void testAuthenticationWrongKey() throws Exception{
        this.authentication = mock(CdaAuthenticationToken.class);

        when(authentication.getName()).thenReturn("atos");
        when(authentication.getCredentials()).thenReturn("atos");
        when(authentication.getKey()).thenReturn("abracadabra");

        _cdaAuthenticationProvider.retrieveUser("atos", authentication);
    }
}
