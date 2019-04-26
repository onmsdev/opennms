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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.time.DateUtils;
import org.junit.Before;
import org.junit.Test;
import org.opennms.core.test.ConfigurationTestUtils;
import org.opennms.core.test.MockLogAppender;
import org.opennms.core.utils.InetAddressUtils;
import org.opennms.netmgt.config.SyslogdConfigFactory;
import org.opennms.netmgt.dao.api.DistPollerDao;
import org.opennms.netmgt.dao.api.MonitoringLocationDao;
import org.opennms.netmgt.dao.hibernate.InterfaceToNodeCacheDaoImpl;
import org.opennms.netmgt.dao.mock.MockInterfaceToNodeCache;
import org.opennms.netmgt.syslogd.BufferParser.BufferParserFactory;
import org.opennms.netmgt.xml.event.Event;
import org.opennms.netmgt.xml.event.Parm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SyslogSinkConsumerMessageTest {
	private static final Logger LOG = LoggerFactory.getLogger(SyslogSinkConsumerMessageTest.class);

	private final SyslogdConfigFactory m_config;

	private static String syslogMessageString;

	public static List<String> grookPatternList = new ArrayList<String>();

	private final ExecutorService m_executor = Executors.newSingleThreadExecutor();

	public SyslogSinkConsumerMessageTest() throws Exception {
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
		MockLogAppender.setupLogging(true, "TRACE");
		grookPatternList = setGrookPatternList(new File(
				this.getClass().getResource("/etc/syslogd-configuration.properties").getPath().replaceAll("%20", " ")));
	}

	public static List<String> setGrookPatternList(File syslogConfigFile) throws IOException {
		return SyslogSinkConsumer.readPropertiesInOrderFrom(syslogConfigFile);
	}

	@Test
	public void testCustomParserWithProcess() throws Exception {
		syslogMessageString = "<6>test: 2007-01-01 127.0.0.1 OpenNMS[1234]: A SyslogNG style message";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar calendar = Calendar.getInstance();
		calendar.set(Calendar.MONTH,Calendar.JANUARY );
		calendar.set(Calendar.DATE, 1);
		calendar.set(Calendar.YEAR, 2007);
		parser.setMinionDate(calendar.getTime());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));

		assertEquals(SyslogFacility.KERNEL, message.getFacility());
		assertEquals(SyslogSeverity.INFORMATIONAL, message.getSeverity());
		assertEquals("test", message.getMessageID());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals("OpenNMS", message.getProcessName());
		assertEquals(1234, message.getProcessId().intValue());
		assertEquals("A SyslogNG style message", message.getMessage());
	}

	@Test
	public void testCustomParserWithSimpleForwardingRegexAndSyslog21Message() throws Exception {
		// see:
		// http://searchdatacenter.techtarget.com/tip/Turn-aggregated-syslog-messages-into-OpenNMS-events

		syslogMessageString = "<173>Dec  7 12:02:06 10.13.110.116 mgmtd[8326]: [mgmtd.NOTICE]: Configuration saved to database initial";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar calendar = Calendar.getInstance();
		calendar.set(Calendar.MONTH, 11);
		calendar.set(Calendar.DATE, 7);
		calendar.set(Calendar.HOUR_OF_DAY, 12);
		calendar.set(Calendar.MINUTE, 2);
		calendar.set(Calendar.SECOND, 6);
		calendar.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(calendar.getTime());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(calendar.getTime(), message.getDate());

		assertEquals(SyslogFacility.LOCAL5, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(null, message.getMessageID());
		assertEquals("10.13.110.116", message.getHostName());
		assertEquals("mgmtd", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("[mgmtd.NOTICE]: Configuration saved to database initial", message.getMessage());
	}


	@Test
	public void testGenericParserWithProcess() throws Exception {

		syslogMessageString = "<6>test: 2007-01-01 127.0.0.1 OpenNMS[1234]: A SyslogNG style message";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 1);
		cal.set(Calendar.YEAR, 2007);
		parser.setMinionDate(cal.getTime());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.KERNEL, message.getFacility());
		assertEquals(SyslogSeverity.INFORMATIONAL, message.getSeverity());
		assertEquals("test", message.getMessageID());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals("OpenNMS", message.getProcessName());
		assertEquals(1234, message.getProcessId().intValue());
		assertEquals("A SyslogNG style message", message.getMessage());
	}

	@Test
	public void testGenericParserWithoutProcess() throws Exception {

		syslogMessageString = "<6>test: 2007-01-01 127.0.0.1 A SyslogNG style message";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 1);
		cal.set(Calendar.YEAR, 2007);
		parser.setMinionDate(cal.getTime());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));

		assertEquals(SyslogFacility.KERNEL, message.getFacility());
		assertEquals(SyslogSeverity.INFORMATIONAL, message.getSeverity());
		assertEquals("test", message.getMessageID());
		assertEquals("127.0.0.1", message.getHostName());
		assertEquals(null, message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals("A SyslogNG style message", message.getMessage());
	}

	@Test
	public void testGenericParserWithSyslog21Message() throws Exception {

		syslogMessageString = "<173>Dec 7 12:02:06 10.13.110.116 mgmtd[8326]: [mgmtd.NOTICE]: Configuration saved to database initial";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.DECEMBER);
		cal.set(Calendar.DAY_OF_MONTH, 7);
		cal.set(Calendar.YEAR, Calendar.getInstance().get(Calendar.YEAR));
		cal.set(Calendar.HOUR_OF_DAY, 12);
		cal.set(Calendar.MINUTE, 2);
		cal.set(Calendar.SECOND, 6);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
		final SyslogMessage message = parser
				.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));

		assertEquals(SyslogFacility.LOCAL5, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(null, message.getMessageID());

		assertEquals(cal.getTime(), message.getDate());
		assertEquals("10.13.110.116", message.getHostName());
		assertEquals("mgmtd", message.getProcessName());
		assertEquals(8326, message.getProcessId().intValue());
		assertEquals("[mgmtd.NOTICE]: Configuration saved to database initial", message.getMessage());
	}

	@Test
	public void testRfc5424ParserExample1() throws Exception {

		syslogMessageString = "<34>1 2003-10-11T22:14:15.000Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
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
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		cal.setTimeZone(TimeZone.getTimeZone("IST"));
		parser.setMinionDate(cal.getTime());
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
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
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
	}

	@Test
	public void testRfc5424ParserExample4() throws Exception {
		syslogMessageString = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"]";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
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
	}

	@Test
	public void testRfc5424ParserExample5() throws Exception {
		syslogMessageString = "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\" eventID=\"1011\"][examplePriority@32473 class=\"high\"] An RFC Parser";
		final GenericParser parser = new GenericParser(m_config, syslogMessageString);
		assertTrue(parser.find());
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.OCTOBER);
		cal.set(Calendar.DAY_OF_MONTH, 11);
		cal.set(Calendar.YEAR, 2003);
		cal.set(Calendar.HOUR_OF_DAY, 22);
		cal.set(Calendar.MINUTE, 14);
		cal.set(Calendar.SECOND, 15);
		cal.set(Calendar.MILLISECOND, 0);
		parser.setMinionDate(cal.getTime());
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
	}

	@Test
	public void testNgStyle() throws Exception {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<34> 10.181.230.67 foo10000: load test 10000 on abc";
		parser = new GenericParser(m_config, syslogMessageString);
		parser.setMinionDate(Calendar.getInstance().getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.AUTH, message.getFacility());
		assertEquals(SyslogSeverity.CRITICAL, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("10.181.230.67", message.getHostName());
		assertEquals("foo10000", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("load test 10000 on abc", message.getMessage());
	}

	@Test
	public void testNgStyleWithDate() throws Exception {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<34> 2007-01-01 10.181.230.67 foo10000: load test 10000 on abc";
		parser = new GenericParser(m_config, syslogMessageString);
		final Calendar cal = Calendar.getInstance();
		cal.set(Calendar.MONTH, Calendar.JANUARY);
		cal.set(Calendar.DAY_OF_MONTH, 1);
		cal.set(Calendar.YEAR, 2007);
		parser.setMinionDate(cal.getTime());
		message = parser.parse(SyslogSinkConsumer.parse(ByteBuffer.wrap(syslogMessageString.getBytes())));
		assertEquals(SyslogFacility.AUTH, message.getFacility());
		assertEquals(SyslogSeverity.CRITICAL, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals("10.181.230.67", message.getHostName());
		assertEquals("foo10000", message.getProcessName());
		assertTrue(DateUtils.isSameDay(cal.getTime(), message.getDate()));
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals("load test 10000 on abc", message.getMessage());
	}

	private List<Parm> getParamsList(ByteBuffer message, String pattern)
			throws InterruptedException, ExecutionException {
		BufferParserFactory grokFactory = GrokParserFactory.parseGrok(pattern);

		CompletableFuture<Event> event = null;

		event = grokFactory.parse(message.asReadOnlyBuffer(), m_executor);
		event.whenComplete((e, ex) -> {
			if (ex == null) {
				// System.out.println(e.toString());
			} else {
				ex.printStackTrace();
			}
		});

		return event.get().getParmCollection();

	}

	@Test
	public void testCiscoParserExample1() throws Exception {
		GenericParser parser;
		SyslogMessage message = null;
		syslogMessageString = "<189>: 2017 Mar  4 15:26:19 CST: %ETHPORT-5-IF_DOWN_ERROR_DISABLED: Interface Ethernet103/1/3 is down (Error disabled. Reason:ekeying triggered)Reply'User profile picture'";
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
		assertEquals(SyslogFacility.LOCAL7, message.getFacility());
		assertEquals(SyslogSeverity.NOTICE, message.getSeverity());
		assertEquals(0, message.getVersion().intValue());
		assertEquals(null, message.getHostName());
		assertEquals("%ETHPORT-5-IF_DOWN_ERROR_DISABLED", message.getProcessName());
		assertEquals(0, message.getProcessId().intValue());
		assertEquals(null, message.getMessageID());
		assertEquals(
				"Interface Ethernet103/1/3 is down (Error disabled. Reason:ekeying triggered)Reply'User profile picture'",
				message.getMessage());
	}


}
