//=============================================================================
//===	Copyright (C) 2001-2012 Food and Agriculture Organization of the
//===	United Nations (FAO-UN), United Nations World Food Programme (WFP)
//===	and United Nations Environment Programme (UNEP)
//===
//===	This program is free software; you can redistribute it and/or modify
//===	it under the terms of the GNU General Public License as published by
//===	the Free Software Foundation; either version 2 of the License, or (at
//===	your option) any later version.
//===
//===	This program is distributed in the hope that it will be useful, but
//===	WITHOUT ANY WARRANTY; without even the implied warranty of
//===	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//===	General Public License for more details.
//===
//===	You should have received a copy of the GNU General Public License
//===	along with this program; if not, write to the Free Software
//===	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
//===
//===	Contact: Jeroen Ticheler - FAO - Viale delle Terme di Caracalla 2,
//===	Rome - Italy. email: geonetwork@osgeo.org
//==============================================================================
package org.fao.geonet.kernel.security.cda;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.fao.geonet.ApplicationContextHolder;
import org.fao.geonet.domain.Profile;
import org.fao.geonet.domain.User;
import org.fao.geonet.repository.UserRepository;
import org.fao.geonet.utils.Log;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.AbstractUserDetailsAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CdaAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
        implements UserDetailsService {

    private static final String CDA_FLAG = "CDA";

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails,
                                                  UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        PasswordEncoder encoder = ApplicationContextHolder.get().getBean(PasswordEncoder.class);


        User gnDetails = (User) userDetails;

        if (authentication.getCredentials() == null) {
            Log.warning(Log.JEEVES, "Authentication failed: no credentials provided");
            throw new BadCredentialsException("Authentication failed: no credentials provided");
        }
    }

    @Override
    protected UserDetails retrieveUser(String username,
                                       UsernamePasswordAuthenticationToken authentication)
            throws AuthenticationException {
        try {
            final ConfigurableApplicationContext applicationContext = ApplicationContextHolder.get();
            CdaConfiguration configuration = ApplicationContextHolder.get().getBean(CdaConfiguration.class);
            UserRepository userRepository = applicationContext.getBean(UserRepository.class);

            // Cast the token to the one we wanted...
            // It is useful so we don't have to recreate this complete class...
            CdaAuthenticationToken authenticationToken = (CdaAuthenticationToken) authentication;

            String uri = configuration.getUri().replace(":key", authenticationToken.getKey().toString());

            // Encoding of the username and password to base64
            String auth = Base64.encodeBase64String((username + ':' + authenticationToken.getCredentials().toString()).getBytes());

            HttpClient client = new DefaultHttpClient();

            HttpPost request = new HttpPost(uri);
            request.addHeader("Authorization", "Basic " + auth);

            // Sending the request
            HttpResponse response = client.execute(request);

            int code = response.getStatusLine().getStatusCode();

            // If code is 200, the server responded us correctly
            // else if code is 403, the provided key is not correct
            // else there is a server side error
            if (code == 200) {
                BufferedReader in = new BufferedReader(
                        new InputStreamReader(response.getEntity().getContent()));
                String inputLine;
                StringBuffer buffer = new StringBuffer();

                while ((inputLine = in.readLine()) != null) {
                    buffer.append(inputLine);
                }

                in.close();

                String data = buffer.toString();

                if (data.equals("OK")) {
                    User user = userRepository.findOneByUsername(username);

                    if (user != null && !user.getSecurity().getAuthType().equalsIgnoreCase(CDA_FLAG)) {
                        throw new AuthenticationServiceException(
                                "Trying to authenticate through CDA a user that is not CDA");
                    }

                    if (user == null) // if user does not exists, add one as guest
                    {
                        user = new User();
                        user.setUsername(username);
                        // We set a profile to registered user, admins will be manually designed
                        user.setProfile(Profile.RegisteredUser);
                        user.setName(username);
                        user.getSecurity().setAuthType(CDA_FLAG);
                        userRepository.saveAndFlush(user);
                    }

                    user.setProfile(Profile.RegisteredUser);
                    userRepository.saveAndFlush(user);

                    return user;
                } else if (data.equals("BAD_CREDENTIALS")) {
                    throw new BadCredentialsException("Wrong credentials");
                }
            } else if (code == 403) {
                throw new BadCredentialsException(messages.getMessage(
                        "CdaAuthenticationProvider.wrongCredentials",
                        "The provided key is not known"));
            } else {
                throw new AuthenticationServiceException("There was an error when accessing the CDA server");
            }
        } catch (Exception e) {
            Log.error(Log.JEEVES, "Unexpected error while loading user", e);
            throw new AuthenticationServiceException("Unexpected error while loading user",e);
        }
        throw new UsernameNotFoundException(username + " is not a valid username");
    }

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {
        return retrieveUser(username, null);
    }

}
