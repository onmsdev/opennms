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

public class CiscoFirewallMessages {

	private final SyslogdConfigFactory m_config;

	private static String syslogMessageString;

	public static List<String> grookPatternList = new ArrayList<String>();

	public CiscoFirewallMessages() throws Exception {
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
	public void CiscoParser1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Mar 17 14:28:48 CST: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Jun 07 2017 01:58:14 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 7);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 58);
		cal.set(Calendar.SECOND, 14);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017-03-06T18:30:00+05:00 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 07);
		cal.set(Calendar.MINUTE, 30);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Mar 11 08:35:17 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 35);
		cal.set(Calendar.SECOND, 17);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2010-08-19 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
	}

	@Test
	public void CiscoParser6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Jun 2 2017 01:59:06: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017 Jul 6 08:42:31 CDT: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017 Jul 6 08:42:31 CDT %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2010-08-19T22:14:15.000Z %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2016-01-22T12:38:53.525708-05:00 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMaxSyslogDropThreshold(43200);
		parser.setMaxSyslogIngestThreshold(5);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 11);
		cal.set(Calendar.MINUTE, 38);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Mar 17 14:28:48 CST:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Jun 07 2017 01:58:14  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 7);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 58);
		cal.set(Calendar.SECOND, 14);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017-03-06T18:30:00+05:00  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 07);
		cal.set(Calendar.MINUTE, 30);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Mar 11 08:35:17  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 35);
		cal.set(Calendar.SECOND, 17);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2010-08-19  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
	}

	@Test
	public void CiscoParser16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: Jun 2 2017 01:59:06:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017 Jul 6 08:42:31 CDT:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2017 Jul 6 08:42:31 CDT  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2010-08-19T22:14:15.000Z  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19>: 2016-01-22T12:38:53.525708-05:00  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 11);
		cal.set(Calendar.MINUTE, 38);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser21() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Mar 17 14:28:48 CST: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser22() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Jun 07 2017 01:58:14 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 7);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 58);
		cal.set(Calendar.SECOND, 14);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser23() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017-03-06T18:30:00+05:00 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 07);
		cal.set(Calendar.MINUTE, 30);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser24() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Mar 11 08:35:17 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 35);
		cal.set(Calendar.SECOND, 17);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser25() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2010-08-19 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
	}

	@Test
	public void CiscoParser26() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Jun 2 2017 01:59:06: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser27() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017 Jul 6 08:42:31 CDT: %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser28() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017 Jul 6 08:42:31 CDT %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser29() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2010-08-19T22:14:15.000Z %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser30() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2016-01-22T12:38:53.525708-05:00 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 11);
		cal.set(Calendar.MINUTE, 38);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser31() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Mar 17 14:28:48 CST:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser32() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Jun 07 2017 01:58:14  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 7);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 58);
		cal.set(Calendar.SECOND, 14);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser33() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017-03-06T18:30:00+05:00  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 07);
		cal.set(Calendar.MINUTE, 30);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser34() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Mar 11 08:35:17  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 35);
		cal.set(Calendar.SECOND, 17);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser35() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2010-08-19  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
	}

	@Test
	public void CiscoParser36() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> Jun 2 2017 01:59:06:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser37() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017 Jul 6 08:42:31 CDT:  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser38() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2017 Jul 6 08:42:31 CDT  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser39() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2010-08-19T22:14:15.000Z  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
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
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void CiscoParser40() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<19> 2016-01-22T12:38:53.525708-05:00  %AUTHPRIV-3-SYSTEM_MSG[8326]: pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 22);
		cal.set(Calendar.YEAR, 2016);
		cal.set(Calendar.HOUR_OF_DAY, 11);
		cal.set(Calendar.MINUTE, 38);
		cal.set(Calendar.SECOND, 53);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("CST"));
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.MAIL, message.getFacility());
		assertEquals(SyslogSeverity.ERROR, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%AUTHPRIV-3-SYSTEM_MSG", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("pam_aaa:Authentication failed from 7.40.16.188 - sshd[20189]", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

}
