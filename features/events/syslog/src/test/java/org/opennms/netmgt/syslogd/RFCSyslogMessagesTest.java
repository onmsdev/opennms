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
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
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

public class RFCSyslogMessagesTest {

	private final SyslogdConfigFactory m_config;

	private static String syslogMessageString;

	public static List<String> grookPatternList = new ArrayList<String>();

	public RFCSyslogMessagesTest() throws Exception {
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
	public void testRfc5424ParserExample1() throws Exception {

		syslogMessageString = "<34>1 2003-10-11T22:14:15.000Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		parser.setMinionDate(cal.getTime());
		assertTrue(parser.find());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));

		assertEquals(1, message.getVersion().intValue());
		assertEquals(SyslogFacility.AUTH, message.getFacility());
		assertEquals(SyslogSeverity.CRITICAL, message.getSeverity());
		assertEquals(cal.getTime(), message.getDate());
		assertEquals("mymachine.example.com", message.getHostName());
		assertEquals("su", message.getProcessName());
		assertEquals("ID47", message.getMessageID());
		assertEquals("'su root' failed for lonvick on /dev/pts/8", message.getMessage());
	}

	@Test
	public void testRfc5424ParserExample2() throws Exception {

		syslogMessageString = "<165>1 2003-10-11T22:14:15.000003-00:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
		parser.setMinionDate(cal.getTime());
		assertTrue(parser.find());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));

		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(1, message.getVersion().intValue());
		assertEquals(cal.getTime(), message.getDate());
		assertEquals("192.0.2.1", message.getHostName());
		assertEquals("myproc", message.getProcessName());
		assertEquals(8710, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("%% It's time to make the do-nuts.", message.getMessage());
	}

	@Test
	public void testRfc5424ParserExample3() throws Exception {
		syslogMessageString = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"] BOMAn application event log entry...";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		assertTrue(parser.find());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(1, message.getVersion().intValue());
		assertEquals("mymachine.example.com", message.getHostName());
		assertEquals("evntslog", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("ID47", message.getMessageID());
		assertEquals("An application event log entry...", message.getMessage());
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

	@Test
	public void testRfc5424ParserExample4() throws Exception {
		syslogMessageString = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		assertTrue(parser.find());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(1, message.getVersion().intValue());
		assertEquals("mymachine.example.com", message.getHostName());
		assertEquals("evntslog", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("ID47", message.getMessageID());
		assertEquals(null, message.getMessage());
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

	@Test
	public void testRfc5424ParserExample5() throws Exception {
		syslogMessageString = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] An RFC Parser";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		assertTrue(parser.find());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.LOCAL4, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(1, message.getVersion().intValue());
		assertEquals("mymachine.example.com", message.getHostName());
		assertEquals("evntslog", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("ID47", message.getMessageID());
		assertEquals("An RFC Parser", message.getMessage());
		cal.setTimeZone(TimeZone.getTimeZone("UTC"));
	}

}
