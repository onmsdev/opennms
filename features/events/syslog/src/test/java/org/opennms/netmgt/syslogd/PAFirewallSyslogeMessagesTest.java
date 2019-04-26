/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2010-2014 The OpenNMS Group, Inc.
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

package org.opennms.netmgt.syslogd;

import static org.junit.Assert.assertEquals;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.TimeZone;
import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.opennms.core.test.ConfigurationTestUtils;
import org.opennms.core.utils.ConfigFileConstants;
import org.opennms.netmgt.config.SyslogdConfigFactory;

public class PAFirewallSyslogeMessagesTest {

	private final SyslogdConfigFactory m_config;

	private static String syslogMessageString;

	public static List<String> grookPatternList = new ArrayList<String>();

	public PAFirewallSyslogeMessagesTest() throws Exception {
		InputStream stream = null;
		try {
			stream = ConfigurationTestUtils.getInputStreamForResource(this, "/etc/syslogd-configuration.xml");
			m_config = new SyslogdConfigFactory(stream);
		} finally {
			if (stream != null) {
				IOUtils.closeQuietly(stream);
			}
		}
	}

	@Before
	public void setUp() throws IOException {
		org.apache.log4j.Logger logger4j = org.apache.log4j.Logger.getRootLogger();
		logger4j.setLevel(org.apache.log4j.Level.toLevel("ERROR"));
		grookPatternList = setGrookPatternList(new File(
				this.getClass().getResource("/etc/syslogd-configuration.properties").getPath().replaceAll("%20", " ")));
	}

	public static List<String> setGrookPatternList(File syslogConfigFile) throws IOException {
		return SyslogSinkConsumer.readPropertiesInOrderFrom(syslogConfigFile);
	}

	@Test
	public void pafirewall1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 01:59:06 kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 2017 01:59:06 kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017-03-06T18:30:00+05:00 kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 19);
		cal.set(Calendar.MINUTE, 00);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017 Mar 4 15:26:19 CST: kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 4);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 15);
		cal.set(Calendar.MINUTE, 26);
		cal.set(Calendar.SECOND, 19);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2010-08-19 kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 2017 01:59:06: kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Mar 17 14:28:48 CST: kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 17);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 14);
		cal.set(Calendar.MINUTE, 28);
		cal.set(Calendar.SECOND, 48);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 42);
		cal.set(Calendar.SECOND, 31);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST6CDT"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2010-08-19T22:14:15.000Z kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 8);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 01:59:06 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 2017 01:59:06 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017-03-06T18:30:00+05:00 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 19);
		cal.set(Calendar.MINUTE, 00);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017 Mar 4 15:26:19 CST: 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 4);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 15);
		cal.set(Calendar.MINUTE, 26);
		cal.set(Calendar.SECOND, 19);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2010-08-19 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Jun  2 2017 01:59:06: 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>Mar 17 14:28:48 CST: 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 17);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 14);
		cal.set(Calendar.MINUTE, 28);
		cal.set(Calendar.SECOND, 48);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2017 Jul 6 08:42:31 CDT 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 42);
		cal.set(Calendar.SECOND, 31);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST6CDT"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2010-08-19T22:14:15.000Z 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

	@Test
	public void pafirewall20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<12>2016-01-22T12:38:53.525708-05:00 1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 8);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(cal.getTime(), message.getDate());
		assertEquals(SyslogFacility.USER, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"1,2017/06/02 01:59:06,0009C102229,THREAT,vulnerability,1,2017/06/02 01:59:06,7.204.66.20,159.140.129.58,0.0.0.0,0.0.0.0,f5 access to internal networks,,,webdav,vsys1,dmz,transit,ethernet1/23,ethernet1/22,CSIRT Threat Logging_Alerting,2017/06/02 01:59:06,34845924,1,54480,80,0,0,0x80000000,tcp,alert,'topic52.html',Multiple Web Servers HTTP_PROXY Traffic Redirection Vulnerability(39595),any,medium,client-to-server,1792131434,0x0,US,US,0,,1346196526810225475,,,24,,,,,,,,0",
				message.getMessage());
	}

}
