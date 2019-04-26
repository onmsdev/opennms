/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2016-2016 The OpenNMS Group, Inc.
 * OpenNMS(R) is Copyright (C) 1999-2016 The OpenNMS Group, Inc.
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

package org.opennms.netmgt.syslogd;

import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.xml.bind.DatatypeConverter;

import org.opennms.netmgt.config.SyslogdConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.joestelmach.natty.DateGroup;
import com.joestelmach.natty.Parser;

public class GenericParser extends SyslogParser {

    public enum Params {
        facilityCode, messageId, hostname, processName, processId, message, version, timestamp,Date
    }
    
    private static final String COMMA=",";
    
    private static final String EMPTY_SPACE=" ";
    
    private static final Logger LOG = LoggerFactory.getLogger(GenericParser.class);
    
    private static Date minionDate;
    
    public static int MAX_SYSLOG_DROP_THRESHOLD_MIN ;

	public static int MAX_SYSLOG_INGEST_THRESHOLD_MIN;

	public void setMaxSyslogDropThreshold(int maxSyslogDropThreshold) {
		MAX_SYSLOG_DROP_THRESHOLD_MIN = maxSyslogDropThreshold;
	}

	public void setMaxSyslogIngestThreshold(int maxSyslogIngestThreshold) {
		MAX_SYSLOG_INGEST_THRESHOLD_MIN = maxSyslogIngestThreshold;
	}
    
    

    public static Date getMinionDate() {
		return minionDate;
	}

	public void setMinionDate(Date minionDate) {
		GenericParser.minionDate = minionDate;
	}

	protected GenericParser(SyslogdConfig config, String text) {
        super(config, text);
    }

    public SyslogMessage parse(Map<String, String> params)
            throws ParseException {
        SyslogMessage syslogMessage = new SyslogMessage();
        Date syslogMessageDate;
        long timeDifference;

        syslogMessage.setParserClass(getClass());
        try {
            int priorityField = parseInteger(getStringTokenValue(params,
                                                                     Params.facilityCode.toString(),
                                                                     "99"));
            syslogMessage.setFacility(SyslogFacility.getFacilityForCode(priorityField));
            syslogMessage.setSeverity(SyslogSeverity.getSeverityForCode(priorityField));
        } catch (final NumberFormatException e) {
            LOG.debug("Unable to parse priority field '{}'", e);
        }

        syslogMessage.setMessageID(getStringTokenValue(params,
                                                       Params.messageId.toString(),
                                                       null));
        syslogMessage.setHostName(getStringTokenValue(params,
                                                      Params.hostname.toString(),
                                                      null));
        syslogMessage.setProcessName(getStringTokenValue(params,
                                                         Params.processName.toString(),
                                                         null));
        syslogMessage.setProcessId(parseInteger(getStringTokenValue(params,
                                                                        Params.processId.toString(),
                                                                       null)));
        syslogMessage.setMessage(getStringTokenValue(params,
                                                     Params.message.toString(),
                                                     null));
        syslogMessage.setVersion(parseInteger(getStringTokenValue(params,
                                                                      Params.version.toString(),
                                                                      "0")));

        syslogMessageDate=getDate(params);

        // Calculating the time differences between syslog message time and
        // minion time
        timeDifference = getDateDiff(syslogMessageDate, getMinionDate(),
                                     TimeUnit.MINUTES);

        // Checking whether syslog message time is ahead by 5 minutes or
        // whether its
        // behind 30 days
        if (timeDifference > -MAX_SYSLOG_INGEST_THRESHOLD_MIN
                && timeDifference <= MAX_SYSLOG_DROP_THRESHOLD_MIN) {
            syslogMessage.setDate(syslogMessageDate);
        } else {
            // If message time is more than 30 days we are dropping messages
            if (timeDifference > MAX_SYSLOG_DROP_THRESHOLD_MIN) {
                throw new ParseException("Dropping syslog message since its more than a month old!",
                                         1);
            }
            syslogMessage.setDate(getMinionDate());
        }
        // changing and setting the time to ISO-8601 format
        syslogMessage.setDateString(ConvertToEvent.getISOTimeStamp(syslogMessageDate));
        
        return syslogMessage;
    }
    
    //Finding the difference between dates
	public static long getDateDiff(Date date1, Date date2, TimeUnit timeUnit) {
	    long diffInMillies = date2.getTime() - date1.getTime();
	    return timeUnit.convert(diffInMillies,TimeUnit.MILLISECONDS);
	}
    
	private Date getDate(Map<String, String> params) throws ParseException {
		if (null != params.get(Params.Date.toString()))
			return tokenizeRfcDate(params.get(Params.Date.toString()));
		return null;
	}

	private int parseInteger(String intValue) {
        try {
            return Integer.parseInt(intValue);
        } catch (NumberFormatException e) {
            return 0;
        } catch (NullPointerException e) {
            return 0;
        }
    }

    /**
     * @param params
     * @param field
     * @param isNullValue
     * @return String token value for the fields like message by breaking from 
     * params
     */
    private String getStringTokenValue(Map<String, String> params,
            String field, String isNullValue) {
        String value;
        StringBuilder messageBuilder=new StringBuilder();
        
		if (null == params.get(field) || params.get(field).isEmpty()) {
			return isNullValue;
		}
		if (params.get(field).equals("-"))
			return isNullValue;

		value = params.get(field);
		if (value.startsWith("BOM")) {
			return value.replaceFirst("BOM", "").trim();

		}
		// To Parse PA Firewall Messages and build a proper meaningfull message
		if (("message").equals(field) && params.get("firewallVersion") != null) {
			messageBuilder.append(params.get("firewallVersion"));
			messageBuilder.append(COMMA);
			messageBuilder.append(params.get("recievedate"));
			messageBuilder.append(EMPTY_SPACE);
			messageBuilder.append(params.get("recievetime"));
			messageBuilder.append(COMMA);
			messageBuilder.append(params.get("serialnumber"));
			messageBuilder.append(COMMA);
			messageBuilder.append(params.get("type"));
			messageBuilder.append(COMMA);
			messageBuilder.append(params.get("subtype"));
			messageBuilder.append(COMMA);
			messageBuilder.append(value);

			return messageBuilder.toString();
		}
        return value.trim();
    }
    
    private static Date tokenizeRfcDate(String dateString) throws ParseException {
		Parser parser = new Parser();
		if(dateString.contains("CDT"))
			dateString=dateString.replace("CDT", "CST6CDT");
		List<DateGroup> groups = parser.parse(dateString);
		for (DateGroup group : groups) {
			return group.getDates().get(0);
		}
		return Calendar.getInstance().getTime();

	}

   
}
