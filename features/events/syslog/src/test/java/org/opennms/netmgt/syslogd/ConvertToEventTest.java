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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.commons.io.IOUtils;
import org.junit.Before;
import org.junit.Test;
import org.opennms.core.ipc.sink.mock.MockMessageDispatcherFactory;
import org.opennms.core.test.ConfigurationTestUtils;
import org.opennms.core.test.MockLogAppender;
import org.opennms.netmgt.config.SyslogdConfigFactory;
import org.opennms.netmgt.dao.api.DistPollerDao;
import org.opennms.netmgt.dao.hibernate.InterfaceToNodeCacheDaoImpl;
import org.opennms.netmgt.dao.mock.MockDistPollerDao;
import org.opennms.netmgt.dao.mock.MockEventIpcManager;
import org.opennms.netmgt.dao.mock.MockInterfaceToNodeCache;
import org.opennms.netmgt.syslogd.SyslogSinkConsumerTest.EventCounter;
import org.opennms.netmgt.syslogd.api.SyslogConnection;
import org.opennms.netmgt.syslogd.api.SyslogMessageLogDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.codahale.metrics.MetricRegistry;

/**
 * Convert to event junit test file to test the performance of Syslogd
 * ConvertToEvent processor
 * 
 * @author ms043660
 */
public class ConvertToEventTest {

	private static final Logger LOG = LoggerFactory.getLogger(ConvertToEventTest.class);

	private final ExecutorService m_executor = Executors.newSingleThreadExecutor();

	private EventCounter m_eventCounter;

//	@Autowired
	private MockEventIpcManager m_eventIpcManager;
//
//	@Autowired
	private DistPollerDao m_distPollerDao;
//
//	@Autowired
//	private Eventd m_eventd;

//	@Autowired
	private SyslogdConfigFactory m_config;

//	@Autowired
	private MockMessageDispatcherFactory<SyslogConnection, SyslogMessageLogDTO> m_messageDispatcherFactory;

	private Syslogd m_syslogd;

	private SyslogSinkConsumer m_syslogSinkConsumer;

	private SyslogSinkModule m_syslogSinkModule;

	public static List<String> grookPatternList = new ArrayList<String>();

	@Before
	public void setUp() throws Exception {
		MockLogAppender.setupLogging(true, "WARN");
		
		loadSyslogConfiguration("/etc/syslogd-loadtest-configuration.xml");
		m_messageDispatcherFactory=new MockMessageDispatcherFactory<>();
		m_eventCounter = new EventCounter();
		m_eventIpcManager=new MockEventIpcManager();
		m_eventIpcManager.addEventListener(m_eventCounter);
		m_distPollerDao=new MockDistPollerDao();
		m_syslogSinkConsumer = new SyslogSinkConsumer(new MetricRegistry());
		m_syslogSinkConsumer.setDistPollerDao(m_distPollerDao);
		m_syslogSinkConsumer.setSyslogdConfig(m_config);
		m_syslogSinkConsumer.setEventForwarder(m_eventIpcManager);
		m_syslogSinkModule = m_syslogSinkConsumer.getModule();
		m_messageDispatcherFactory.setConsumer(m_syslogSinkConsumer);
		grookPatternList = setGrookPatternList(new File(
				this.getClass().getResource("/etc/syslogd-configuration.properties").getPath().replaceAll("%20", " ")));
		m_syslogSinkConsumer.setGrokPatternsList(grookPatternList);
	}

	public static List<String> setGrookPatternList(File syslogConfigFile) throws IOException {
		return SyslogSinkConsumer.readPropertiesInOrderFrom(syslogConfigFile);
	}
	
	private void loadSyslogConfiguration(final String configuration) throws IOException {
		InputStream stream = null;
		try {
			stream = ConfigurationTestUtils.getInputStreamForResource(this, configuration);
			m_config = new SyslogdConfigFactory(stream);
		} finally {
			if (stream != null) {
				IOUtils.closeQuietly(stream);
			}
		}
		if (m_syslogSinkConsumer != null) {
			m_syslogSinkConsumer.setSyslogdConfig(m_config);
			m_syslogSinkModule = m_syslogSinkConsumer.getModule();
		}
	}

	/**
	 * Test method which calls the ConvertToEvent constructor.
	 * 
	 * @throws MarshalException
	 * @throws ValidationException
	 * @throws IOException
	 */
	@Test
	public void testConvertToEvent() throws IOException {
		try {
			InterfaceToNodeCacheDaoImpl.setInstance(new MockInterfaceToNodeCache());

			byte[] bytes = "<34> 2018-05-06 localhost foo10000: load test 10000 on tty1".getBytes();
			m_eventCounter.anticipate();
			m_syslogSinkConsumer.handleMessage(getMessageLog(bytes));
			assertEquals(1, m_eventCounter.getCount());
		} catch (Exception e) {
			LOG.error("Message Parsing failed", e);
			fail("Message Parsing failed: " + e.getMessage());
		}
	}

	private SyslogMessageLogDTO getMessageLog(byte[] messageBytes) throws UnknownHostException {

		DatagramPacket pkt = new DatagramPacket(messageBytes, messageBytes.length, InetAddress.getLocalHost(),
				SyslogClient.PORT);
		return m_syslogSinkModule.toMessageLog(new SyslogConnection(pkt, false));
	}

	@Test
	public void testCiscoEventConversion() throws IOException {

		byte[] bytes = "<190>May 06 08:35:17 127.0.0.1 30128311[4]: Mar 11 08:35:16.844 CST: %SEC-6-IPACCESSLOGP: list in110 denied tcp 192.168.10.100(63923) -> 192.168.11.128(1521), 1 packet"
				.getBytes();

		m_eventCounter.anticipate();
		m_syslogSinkConsumer.handleMessage(getMessageLog(bytes));
		assertEquals(1, m_eventCounter.getCount());
	}
	
	
	@Test
	public void testPastDateEvent() throws IOException {

		byte[] bytes = "<190>Jan 06 08:35:17 127.0.0.1 30128311[4]: Mar 11 08:35:16.844 CST: %SEC-6-IPACCESSLOGP: list in110 denied tcp 192.168.10.100(63923) -> 192.168.11.128(1521), 1 packet"
				.getBytes();

		m_eventCounter.anticipate();
		m_syslogSinkConsumer.handleMessage(getMessageLog(bytes));
		assertEquals(0, m_eventCounter.getCount());
	}

}
