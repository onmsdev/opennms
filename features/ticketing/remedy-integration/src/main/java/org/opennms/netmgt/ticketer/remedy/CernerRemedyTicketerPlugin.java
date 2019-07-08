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

import java.util.Map;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.opennms.api.integration.ticketing.Plugin;
import org.opennms.api.integration.ticketing.PluginException;
import org.opennms.api.integration.ticketing.Ticket;
import org.opennms.api.integration.ticketing.Ticket.State;
import org.opennms.core.resource.Vault;
import org.opennms.netmgt.ticketer.remedy.bean.Incident;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

/**
 * OpenNMS Trouble Ticket Plugin API implementation for Remedy
 *
 * @author <a href="mailto:jonathan@opennms.org">Jonathan Sartin</a>
 * @author <a href="antonio@opennms.it">Antonio Russo</a>
 * @version $Id: $
 */
public class CernerRemedyTicketerPlugin implements Plugin {

	private static final Logger LOG = LoggerFactory.getLogger(RemedyTicketerPlugin.class);
	private static final String INCIDENT_STR = "incidentID";
	private static final String INCIDENT_STATUS_NEW = "New";

	public Ticket get(String ticketId) throws PluginException {
		return null;
	}

	private State remedyToOpenNMSState(StatusType status) {
		State state = State.OPEN;
		if (status.toString().equals(StatusType.CLOSED.getStatus())
				|| status.toString().equals(StatusType.RESOLVED.getStatus())) {
			state = State.CLOSED;
		} else if (status.toString().equals(StatusType.CANCELLED.getStatus()))
			state = State.CANCELLED;
		return state;
	}

	@Override
	public void saveOrUpdate(Ticket ticket) throws PluginException {

		if ((ticket.getId() == null)) {
			save(ticket);
		} else {
			update(ticket);
		}
	}

	private void save(Ticket ticket) throws PluginException {

		try {
			ResourceConfiguration resourceConfig = getResourceConfig();
			OAuth2RestTemplate restTemplate = resourceConfig.restTemplate();

			Incident incident = getIncidentData(ticket, INCIDENT_STATUS_NEW);
			HttpHeaders headers = getHeaders();

			// Set error handler for OAuth2RestTemplate
			restTemplate.setErrorHandler(new RestTemplateResponseErrorHandler());
			HttpEntity<Incident> httpEntity = new HttpEntity<>(incident, headers);
			ResponseEntity<String> response = restTemplate.exchange(resourceConfig.getRapidIncidentUri(),
					HttpMethod.POST, httpEntity, String.class);
			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(response.getBody());
			String incidentId = (String) jsonObject.get(INCIDENT_STR);
			LOG.debug("created new remedy ticket with reported incident number: {}", incidentId);
			ticket.setId(incidentId);
		}

		catch (Exception e) {
			LOG.error("Problem saving ticket:alarmId {}", ticket.getAlarmId());
			throw new PluginException("Problem saving ticket", e);

		}

	}

	/*
	 * Get Singleton instance of ResourceConfiguration
	 */
	private ResourceConfiguration getResourceConfig() {
		ApplicationContext applicationContext = ApplicationContextProvider.getContext();
		return applicationContext.getBean("resourceConfiguration", ResourceConfiguration.class);

	}

	private void update(Ticket ticket) throws PluginException{

		try {
			ResourceConfiguration resourceConfig = getResourceConfig();
			OAuth2RestTemplate restTemplate = resourceConfig.restTemplate();

			Incident incident = getIncidentData(ticket, INCIDENT_STATUS_NEW);
			HttpHeaders headers = getHeaders();

			// Set error handler for OAuth2RestTemplate
			restTemplate.setErrorHandler(new RestTemplateResponseErrorHandler());
			HttpEntity<Incident> httpEntity = new HttpEntity<>(incident, headers);
			ResponseEntity<String> response = restTemplate.exchange(resourceConfig.getRapidIncidentUri(),
					HttpMethod.PUT, httpEntity, String.class);
			JSONParser jsonParser = new JSONParser();
			JSONObject jsonObject = (JSONObject) jsonParser.parse(response.getBody());
			String incidentId = (String) jsonObject.get(INCIDENT_STR);
			LOG.debug("created new remedy ticket with reported incident number: {}", incidentId);
			ticket.setId(incidentId);
		}

		catch (Exception e) {
			throw new PluginException("Problem updating ticket", e);

		}

	}

	/*
	 * Get Incident object from Ticket obj
	 */
	private Incident getIncidentData(Ticket ticket, String incidentStatus) {
		
		Configuration configuration = extractRemedyProperties();
		System.out.println(configuration.getString("remedy.serviceType"));
		Map<String, String> attributes = ticket.getAttributes();
		String impact = configuration.getString("remedy.impact");
		String incidentType = configuration.getString("remedy.serviceType");
		String urgency = attributes.get("remedy.urgency");
		String summary = ticket.getSummary();
		Incident incident = new Incident(impact, incidentStatus, incidentType, urgency, summary);

		// Setting incidentContactID, impersonateUserAs, incidentRequestorID
		incident.addUser("dp044946");
		// incident.addUser(ticket.getUser());

		incident.setAssignedGroup(attributes.get("remedy.assignedgroup"));
		incident.setAssignedGroupCompany(configuration.getString("remedy.assignedGroupCompany"));
		incident.setIntegrationID(configuration.getString("remedy.integrationID"));
		incident.setNotes(attributes.get("remedy.user.comment"));
		incident.setOperationalCategorizationTier1(configuration.getString("remedy.operationalCategorizationTier1"));
		incident.setProductCategorizationTier1(configuration.getString("remedy.productCategorizationTier1"));
		
		incident.setReportedSource(configuration.getString("remedy.reportedSource"));
		incident.setCareImpactReview(configuration.getString("remedy.careImpactReview"));
		incident.setTargetDate(configuration.getString("remedy.targetDate"));
		incident.setIncidentTemplate(attributes.get("remedy.incident.template"));
		return incident;
	}

	private Configuration extractRemedyProperties() {
		String propsFile = new String(Vault.getProperty("opennms.home") + "/etc/remedy.properties");
        Configuration remedyConfig = null;
          try {
			remedyConfig = new PropertiesConfiguration(propsFile);
		} catch (ConfigurationException e) {
			
			e.printStackTrace();
		}
          return remedyConfig;
	}

	/**
	 * @return HttpHeaders
	 */
	private HttpHeaders getHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return headers;
	}

}
