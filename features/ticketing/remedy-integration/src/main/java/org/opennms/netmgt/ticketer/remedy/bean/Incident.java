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
package org.opennms.netmgt.ticketer.remedy.bean;

public class Incident {

	private Impersonation impersonation = new Impersonation();
	private String assignedGroup;
	private String assignedGroupCompany;
	private String impact;
	private String incidentContactID;
	private String incidentRequestorID;
	private String incidentStatus;
	private String incidentStatusReason;
	private String incidentType;
	private String integrationID;
	private String notes;
	private String operationalCategorizationTier1;
	private String productCategorizationTier1;
	private String reportedSource;
	private String summary;
	private String careImpactReview;
	private String targetDate;
	private String urgency;
	private String incidentTemplate;

	public Incident(String impact, String incidentStatus, String incidentType, String urgency, String summary) {
		this.impact = impact;
		this.incidentStatus = incidentStatus;
		this.incidentType = incidentType;
		this.urgency = urgency;
		this.summary = summary;
	}

	public Incident() {
		super();
	}

	public Incident addUser(String reportedUser) {
		this.incidentContactID = reportedUser;
		this.incidentRequestorID = reportedUser;
		this.impersonation.setImpersonateUserAs(reportedUser);
		return this;
	}

	public Impersonation getImpersonation() {
		return impersonation;
	}

	public void setImpersonation(Impersonation impersonation) {
		this.impersonation = impersonation;
	}

	public String getAssignedGroup() {
		return assignedGroup;
	}

	public void setAssignedGroup(String assignedGroup) {
		this.assignedGroup = assignedGroup;
	}

	public String getAssignedGroupCompany() {
		return assignedGroupCompany;
	}

	public void setAssignedGroupCompany(String assignedGroupCompany) {
		this.assignedGroupCompany = assignedGroupCompany;
	}

	public String getImpact() {
		return impact;
	}

	public void setImpact(String impact) {
		this.impact = impact;
	}

	public String getIncidentContactID() {
		return incidentContactID;
	}

	public void setIncidentContactID(String incidentContactID) {
		this.incidentContactID = incidentContactID;
	}

	public String getIncidentRequestorID() {
		return incidentRequestorID;
	}

	public void setIncidentRequestorID(String incidentRequestorID) {
		this.incidentRequestorID = incidentRequestorID;
	}

	public String getIncidentStatus() {
		return incidentStatus;
	}

	public void setIncidentStatus(String incidentStatus) {
		this.incidentStatus = incidentStatus;
	}

	public String getIncidentStatusReason() {
		return incidentStatusReason;
	}

	public void setIncidentStatusReason(String incidentStatusReason) {
		this.incidentStatusReason = incidentStatusReason;
	}

	public String getIncidentType() {
		return incidentType;
	}

	public void setIncidentType(String incidentType) {
		this.incidentType = incidentType;
	}

	public String getIntegrationID() {
		return integrationID;
	}

	public void setIntegrationID(String integrationID) {
		this.integrationID = integrationID;
	}

	public String getNotes() {
		return notes;
	}

	public void setNotes(String notes) {
		this.notes = notes;
	}

	public String getOperationalCategorizationTier1() {
		return operationalCategorizationTier1;
	}

	public void setOperationalCategorizationTier1(String operationalCategorizationTier1) {
		this.operationalCategorizationTier1 = operationalCategorizationTier1;
	}

	public String getProductCategorizationTier1() {
		return productCategorizationTier1;
	}

	public void setProductCategorizationTier1(String productCategorizationTier1) {
		this.productCategorizationTier1 = productCategorizationTier1;
	}

	public String getReportedSource() {
		return reportedSource;
	}

	public void setReportedSource(String reportedSource) {
		this.reportedSource = reportedSource;
	}

	public String getSummary() {
		return summary;
	}

	public void setSummary(String summary) {
		this.summary = summary;
	}

	public String getCareImpactReview() {
		return careImpactReview;
	}

	public void setCareImpactReview(String careImpactReview) {
		this.careImpactReview = careImpactReview;
	}

	public String getTargetDate() {
		return targetDate;
	}

	public void setTargetDate(String targetDate) {
		this.targetDate = targetDate;
	}

	public String getUrgency() {
		return urgency;
	}

	public void setUrgency(String urgency) {
		this.urgency = urgency;
	}

	public String getIncidentTemplate() {
		return incidentTemplate;
	}

	public void setIncidentTemplate(String incidentTemplate) {
		this.incidentTemplate = incidentTemplate;
	}

}
