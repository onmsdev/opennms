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

public class CustomSyslogMessages {

	private final SyslogdConfigFactory m_config;

	private static String syslogMessageString;

	public static List<String> grookPatternList = new ArrayList<String>();

	public CustomSyslogMessages() throws Exception {
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
	public void WithoutProcessName1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 07 2017 01:58:14 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName2() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun  2 01:59:06  [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutProcessName3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017-03-06T18:30:00+05:00 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Mar 11 08:35:17 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutProcessName6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 2017 01:59:06: [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT: [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19T22:14:15.000Z [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2016-01-22T12:38:53.525708-05:00 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 07 2017 01:58:14 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun  2 01:59:06  kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017-03-06T18:30:00+05:00 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Mar 11 08:35:17 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMaxSyslogDropThreshold(43200);
                parser.setMaxSyslogIngestThreshold(5);
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutProcessName16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 2017 01:59:06: kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19T22:14:15.000Z kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutProcessName20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<6>test: 2007-01-01 127.0.0.1 A SyslogNG style message";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 1);
		cal.set(Calendar.YEAR, 2007);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.KERNEL, message.getFacility());
		assertEquals(SyslogSeverity.INFORMATIONAL, message.getSeverity());
		assertEquals("test", message.getMessageID());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("A SyslogNG style message", message.getMessage());

	}

	@Test
	public void WithMessageIdWithoutProcessNameId2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 2017 01:59:06 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithMessageIdWithoutProcessNameId3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 127.0.0.1 A SyslogNG style message";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MARCH);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 07);
		cal.set(Calendar.MINUTE, 30);
		cal.set(Calendar.SECOND, 00);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Mar 4 15:26:19 CST: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithMessageIdWithoutProcessNameId5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 127.0.0.1 A SyslogNG style message";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithMessageIdWithoutProcessNameId10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<6> 2007-01-01 127.0.0.1 A SyslogNG style message";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 1);
		cal.set(Calendar.YEAR, 2007);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.KERNEL, message.getFacility());
		assertEquals(SyslogSeverity.INFORMATIONAL, message.getSeverity());
		assertEquals(null, message.getMessageID());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("A SyslogNG style message", message.getMessage());

	}

	@Test
	public void WithoutMessageIdProcessNameId2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun  2 2017 01:59:06 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutMessageIdProcessNameId3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017-03-06T18:30:00+05:00 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Mar 4 15:26:19 CST: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutMessageIdProcessNameId5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19 127.0.0.1 A SyslogNG style message";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
	}

	@Test
	public void WithoutMessageIdProcessNameId6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 2017 01:59:06: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT: 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19T22:14:15.000Z 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		// assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutMessageIdProcessNameId10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2016-01-22T12:38:53.525708-05:00 127.0.0.1 A SyslogNG style message";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("A SyslogNG style message", message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 01:59:06  kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostName2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 2017 01:59:06 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostName3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Mar 4 15:26:19 CST: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostName5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostName6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 07 2017 01:58:14 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 01:59:06  kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Mar 11 08:35:17 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostName16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostName20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 01:59:06  %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutHostname2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 2017 01:59:06 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutHostname3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Mar 4 15:26:19 CST: %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithoutHostname5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutHostname6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 07 2017 01:58:14 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 01:59:06  %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Mar 11 08:35:17 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutHostname16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithoutHostname20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 07 2017 01:58:14 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 01:59:06  [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Mar 11 08:35:17 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostNameWithoutProcessName6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);	final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JUNE);
		cal.set(Calendar.DAY_OF_MONTH, 2);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 01);
		cal.set(Calendar.MINUTE, 59);
		cal.set(Calendar.SECOND, 06);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 07 2017 01:58:14 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun  2 01:59:06  kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017-03-06T18:30:00+05:00 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Mar 11 08:35:17 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostNameWithoutProcessName16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:Jun 2 2017 01:59:06: kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2010-08-19T22:14:15.000Z kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostNameWithoutProcessName20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test:2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 [8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	

	@Test
	public void WithHostnameWithoutMessageId1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 01:59:06  kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostnameWithoutMessageId2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun  2 2017 01:59:06 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostnameWithoutMessageId3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017-03-06T18:30:00+05:00 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Mar 4 15:26:19 CST: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}

	@Test
	public void WithHostnameWithoutMessageId5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostnameWithoutMessageId6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 2017 01:59:06: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19T22:14:15.000Z kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 07 2017 01:58:14 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun  2 01:59:06  kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017-03-06T18:30:00+05:00 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Mar 11 08:35:17 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.AUGUST);
		cal.set(Calendar.DAY_OF_MONTH, 19);
		cal.set(Calendar.YEAR, 2010);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithHostnameWithoutMessageId16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>Jun 2 2017 01:59:06: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2017 Jul 6 08:42:31 CDT kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2010-08-19T22:14:15.000Z kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}

	@Test
	public void WithHostnameWithoutMessageId20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>2016-01-22T12:38:53.525708-05:00 kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
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
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());
	}
	
	@Test
	public void WithoutDate1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutDate2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutDate3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutDate5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate21() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate22() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate23() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate24() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate25() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate26() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate27() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate28() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate29() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutDate30() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164>test: %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("test", message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate1() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutMessageIdDate2() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutMessageIdDate3() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate4() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());

	}

	@Test
	public void WithoutMessageIdDate5() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate6() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate7() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate8() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate9() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate10() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate11() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate12() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate13() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate14() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate15() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate16() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate17() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate18() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate19() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate20() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> kc2dmz-fw-01 %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("kc2dmz-fw-01", message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate21() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate22() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate23() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate24() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate25() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate26() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate27() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate28() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate29() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}

	@Test
	public void WithoutMessageIdDate30() throws ParseException, IOException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<164> %ASA-4-106023[8326]: Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.WARNING, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ASA-4-106023", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Deny udp src inside:10.35.0.108/34870 dst outside:159.140.177.185/389 by access-group 'in110' [0x8870d135, 0x0]",
				message.getMessage());
	}
	
	
	@Test
	public void fireWallMessage1() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: May  5 23:53:47: %SYS-5-PRIV_AUTH_FAIL: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MAY);
		cal.set(Calendar.DAY_OF_MONTH, 5);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 53);
		cal.set(Calendar.SECOND, 47);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage2() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: May  5 23:53:47: %SYS-5-PRIV_AUTH_FAIL[8326]: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MAY);
		cal.set(Calendar.DAY_OF_MONTH, 5);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 53);
		cal.set(Calendar.SECOND, 47);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage3() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: May  5 23:53:47: [8326]: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.MAY);
		cal.set(Calendar.DAY_OF_MONTH, 5);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 23);
		cal.set(Calendar.MINUTE, 53);
		cal.set(Calendar.SECOND, 47);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage4() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: 2017 Jul 6 08:42:31: %SYS-5-PRIV_AUTH_FAIL: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 42);
		cal.set(Calendar.SECOND, 31);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage5() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: 2017 Jul 6 08:42:31: %SYS-5-PRIV_AUTH_FAIL[8326]: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 42);
		cal.set(Calendar.SECOND, 31);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage6() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: 2017 Jul 6 08:42:31: [8326]: Test syslog for outage";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JULY);
		cal.set(Calendar.DAY_OF_MONTH, 6);
		cal.set(Calendar.YEAR, 2017);
		cal.set(Calendar.HOUR_OF_DAY, 8);
		cal.set(Calendar.MINUTE, 42);
		cal.set(Calendar.SECOND, 31);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage7() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: Jun 2 2017 01:59:06: %SYS-5-PRIV_AUTH_FAIL: Test syslog for outage";
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
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage8() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: Jun 2 2017 01:59:06: %SYS-5-PRIV_AUTH_FAIL[8326]: Test syslog for outage";
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
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%SYS-5-PRIV_AUTH_FAIL", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	@Test
	public void fireWallMessage9() throws ParseException, IOException, MessageDiscardedException {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>1163: Jun 2 2017 01:59:06: [8326]: Test syslog for outage";
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
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("1163", message.getMessageID());
		assertEquals(
				"Test syslog for outage",
				message.getMessage());
		assertEquals(cal.getTime(), message.getDate());

	}
	
	

}
