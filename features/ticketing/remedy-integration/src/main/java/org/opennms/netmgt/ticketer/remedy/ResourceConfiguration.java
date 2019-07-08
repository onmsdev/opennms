/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2013-2014 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2014 The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is a registered trademark of The OpenNMS Group, Inc.
 *
 * OpenNMS(R) is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * OpenNMS(R) is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with OpenNMS(R).  If not, see:
 *      http://www.gnu.org/licenses/
 *
 * For more information contact:
 *     OpenNMS(R) Licensing <license@opennms.org>
 *     http://www.opennms.org/
 *     http://www.opennms.com/
 *******************************************************************************/
package org.opennms.netmgt.ticketer.remedy;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;

@Configuration
@EnableOAuth2Client
@PropertySource(ignoreResourceNotFound = true, value = "classpath:rapid.properties")
public class ResourceConfiguration {

	@Value("${rapid.client.id}")
    private String clientID;

    @Value("${rapid.client.secret}")
    private String clientSecret;

    @Value("${rapid.accesstoken.uri}")
    private String accessTokenUri;

    @Value("${rapid.incident.uri}")
    private String rapidIncidentUri;

	
	public String getClientID() {
		return clientID;
	}

	public void setClientID(String clientID) {
		this.clientID = clientID;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getAccessTokenUri() {
		return accessTokenUri;
	}

	public void setAccessTokenUri(String accessTokenUri) {
		this.accessTokenUri = accessTokenUri;
	}

	public String getRapidIncidentUri() {
		return rapidIncidentUri;
	}

	public void setRapidIncidentUri(String rapidIncidentUri) {
		this.rapidIncidentUri = rapidIncidentUri;
	}

	@Bean
	public ClientCredentialsResourceDetails resource() {
		ClientCredentialsResourceDetails resource = new ClientCredentialsResourceDetails();
		resource.setAccessTokenUri(accessTokenUri);
		resource.setClientId(clientID);
		resource.setClientSecret(clientSecret);
		return resource;
	}

	@Bean
	public OAuth2RestTemplate restTemplate() {
		DefaultAccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest();
		OAuth2ClientContext auth2ClientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
		OAuth2RestTemplate oAuth2RestTemplate = new OAuth2RestTemplate(resource(), auth2ClientContext);

		return oAuth2RestTemplate;
	}

}
