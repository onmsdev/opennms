/*******************************************************************************
 * This file is part of OpenNMS(R).
 *
 * Copyright (C) 2002-2016 The OpenNMS Group, Inc.
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

import static org.opennms.core.utils.InetAddressUtils.addr;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.opennms.core.ipc.sink.api.MessageConsumer;
import org.opennms.core.ipc.sink.api.MessageConsumerManager;
import org.opennms.core.logging.Logging;
import org.opennms.core.logging.Logging.MDCCloseable;
import org.opennms.core.utils.ConfigFileConstants;
import org.opennms.core.utils.InetAddressUtils;
import org.opennms.netmgt.config.SyslogdConfig;
import org.opennms.netmgt.dao.api.DistPollerDao;
import org.opennms.netmgt.events.api.EventConstants;
import org.opennms.netmgt.events.api.EventForwarder;
import org.opennms.netmgt.model.events.EventBuilder;
import org.opennms.netmgt.syslogd.BufferParser.BufferParserFactory;
import org.opennms.netmgt.syslogd.api.SyslogConnection;
import org.opennms.netmgt.syslogd.api.SyslogMessageDTO;
import org.opennms.netmgt.syslogd.api.SyslogMessageLogDTO;
import org.opennms.netmgt.xml.event.Event;
import org.opennms.netmgt.xml.event.Events;
import org.opennms.netmgt.xml.event.Log;
import org.opennms.netmgt.xml.event.Parm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.Timer;
import com.codahale.metrics.Timer.Context;

public class SyslogSinkConsumer implements MessageConsumer<SyslogConnection, SyslogMessageLogDTO>, InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(SyslogSinkConsumer.class);

    @Autowired
    private MessageConsumerManager messageConsumerManager;

    @Autowired
    private SyslogdConfig syslogdConfig;

    @Autowired
    private DistPollerDao distPollerDao;

    @Autowired
    private EventForwarder eventForwarder;

    private final String localAddr;
    private final Timer consumerTimer;
    private final Timer toEventTimer;
    private final Timer broadcastTimer;

	private  final String SOURCE_ADDRESS="source_address=";
    
    private final static ExecutorService m_executor = Executors.newSingleThreadExecutor();
    
    public enum CalenderConstant {
    	year, day, month, hours, minutes, seconds, milliseconds, timeOffsets,timeZone,UTC
    }
    
	final static String[] OFFSETS = { "UTC", "utc", "IST", "ist", "CDT", "cdt", "CST", "cst" };
	
	private static final Pattern m_monthDatePatternWithTimeZone=Pattern.compile("[a-zA-Z]{3}\\s{1}\\d{2}\\s{1}\\d{4}\\s{1}\\d{2}:\\d{2}:\\d{2}\\s\\w{3}", Pattern.MULTILINE);
	
	private static final Pattern m_monthDateWithoutYearPatternWithTimeZone=Pattern.compile("[a-zA-Z]{3}\\s{1}\\d{2}\\s{1}\\d{2}:\\d{2}:\\d{2}\\s\\w{3}", Pattern.MULTILINE);

	private static final Pattern m_monthDatePatternWithOutTimeZone=Pattern.compile("[a-zA-Z]{3}\\s{1}\\d{2}\\s{1}\\d{4}\\s{1}\\d{2}:\\d{2}:\\d{2}", Pattern.MULTILINE);
	
	private static final Pattern m_monthDateWithoutYearPatternWithOutTimeZone=Pattern.compile("[a-zA-Z]{3}\\s{1}\\d{2}\\s{1}\\d{2}:\\d{2}:\\d{2}", Pattern.MULTILINE);

	private static final Pattern m_dateWithOffset=Pattern.compile("\\d{2}-\\d{2}-\\d{4}\\s\\d{2}:\\d{2}:\\d{2}\\[+-]\\d{2}:\\d{2}", Pattern.MULTILINE);
	
	private static final Pattern m_dateWithOffsetWithMilliseconds=Pattern.compile("\\d{4}-\\d{2}-\\d{2}\\w{1}\\d{2}:\\d{2}:\\d{2}[+-]\\d{2}:\\d{2}", Pattern.MULTILINE);
	
	
	private static final Pattern m_basicDatePatter=Pattern.compile("\\d{2}-\\d{2}-\\d{4}\\s\\d*:\\d*:\\d*", Pattern.MULTILINE);
	
	private static final Pattern m_utcDatePattern=Pattern.compile("\\d{2}-\\d{2}-\\d{4}\\s\\d*:\\d*:\\d*\\s\\w{3}", Pattern.MULTILINE);
	
	  private static final String IPADDRESS_PATTERN = 
				"^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
				"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
				"([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\." +
				"([01]?\\d\\d?|2[0-4]\\d|25[0-5])$";
	
	private static final Pattern m_ipaddressPattern=Pattern.compile(IPADDRESS_PATTERN, Pattern.MULTILINE);
	
	private static final Pattern m_hostname=Pattern.compile("[a-zA-Z0-9]+[.-]+[a-zA-Z0-9]+[.-]*[a-zA-Z0-9]*", Pattern.MULTILINE);
    
    private static List<String> grokPatternsList;
    
    private static List<Pattern> datePatternList;
    
    private static final String DATE="Date";
    
    private static final String HOSTNAME="hostname";
    
    private static final String PROCESS_NAME="processName";
    
    private static final String OFFSET_DELIMITER="Z";
    
    private static final String LOCALHOST="localhost";
    
	public static final String MAX_SYSLOG_DROP_THRESHOLD_MIN ="MAX_SYSLOG_DROP_THRESHOLD_MIN";
	
	public static final String MAX_SYSLOG_INGEST_THRESHOLD_MIN="MAX_SYSLOG_INGEST_THRESHOLD_MIN";
    
    public static List<String> getGrokPatternsList() {
        return grokPatternsList;
    }
    
	private static Map<String, String> syslodTimestampProperties;
    
	private static Date minionTimeStamp;
	
	public static Date getMinionTimeStamp() {
		return minionTimeStamp;
	}

	public void setMinionTimeStamp(Date minionsTimeStamp) {
		minionTimeStamp = minionsTimeStamp;
	}

    public void setGrokPatternsList(List<String> grokPatternsListValue) {
        grokPatternsList = grokPatternsListValue;
    }

    public SyslogSinkConsumer(MetricRegistry registry) {
        consumerTimer = registry.timer("consumer");
        toEventTimer = registry.timer("consumer.toevent");
        broadcastTimer = registry.timer("consumer.broadcast");
        localAddr = InetAddressUtils.getLocalHostName();
    }

    @Override
    public SyslogSinkModule getModule() {
        return new SyslogSinkModule(syslogdConfig, distPollerDao);
    }
   
    /**
     * Static block to load grokPatterns during the start of SyslogSink class call.
     */
    static {
        try {
            loadGrokParserList();
            loadSyslodTimestampProperties();
            loadDatePatternList();
        } catch (IOException e) {
            LOG.debug("Failed to load Grok pattern list."+e);
        }

    }

    public static void loadGrokParserList() throws IOException {
        grokPatternsList = new ArrayList<String>();
        File syslogConfigFile = ConfigFileConstants
                .getFile(ConfigFileConstants.SYSLOGD_CONFIGURATION_PROPERTIES);
        readPropertiesInOrderFrom(syslogConfigFile);
    }
    
	private static void loadDatePatternList() {
		datePatternList=new ArrayList<Pattern>();
		datePatternList.add(m_monthDatePatternWithTimeZone);
		datePatternList.add(m_monthDateWithoutYearPatternWithTimeZone);
		datePatternList.add(m_monthDatePatternWithOutTimeZone);
		datePatternList.add(m_monthDateWithoutYearPatternWithOutTimeZone);
		datePatternList.add(m_dateWithOffset);
		datePatternList.add(m_dateWithOffsetWithMilliseconds);
		datePatternList.add(m_basicDatePatter);
		datePatternList.add(m_utcDatePattern);
	}

	private static void loadSyslodTimestampProperties() {
		try {
			syslodTimestampProperties = readPropertiesInOrderFromToMap(
					ConfigFileConstants.getFile(ConfigFileConstants.SYSLOGD_TIME_PROPERITES));
		} catch (Exception e) {
			LOG.error("Failed to load syslogd timestamp properties and properties file !" + e.getMessage());
		}
	}

	@Override
    public void handleMessage(SyslogMessageLogDTO syslogDTO) {
        try (Context consumerCtx = consumerTimer.time()) {
            try (MDCCloseable mdc = Logging.withPrefixCloseable(Syslogd.LOG4J_CATEGORY)) {
                // Convert the Syslog UDP messages to Events
                final Log eventLog;
                try (Context toEventCtx = toEventTimer.time()) {
                    eventLog = toEventLog(syslogDTO);
                }
                // Broadcast the Events to the event bus
                try (Context broadCastCtx = broadcastTimer.time()) {
                    broadcast(eventLog);
                }
            }
        }
    }

    public Log toEventLog(SyslogMessageLogDTO messageLog) {
        final Log elog = new Log();
        final Events events = new Events();
        elog.setEvents(events);
        for (SyslogMessageDTO message : messageLog.getMessages()) {
            try {
            	   //Adding source address to syslog header
            	   String syslogString = new String(message.getBytes().array());
            	   
            		if (syslodTimestampProperties != null && syslodTimestampProperties.size() == 2) {
            			messageLog.setMaxSyslogDropThresholdMin(
        						Integer.parseInt(syslodTimestampProperties.get(MAX_SYSLOG_DROP_THRESHOLD_MIN)));
            			messageLog.setMaxSyslogIngestThresholdMin(Integer
        						.parseInt(syslodTimestampProperties.get(MAX_SYSLOG_INGEST_THRESHOLD_MIN)));
        			} else {
        				messageLog.setMaxSyslogDropThresholdMin(43200);
        				messageLog.setMaxSyslogIngestThresholdMin(5);
        			}
            	   
                   if (syslogString.contains(SOURCE_ADDRESS)) {
           			String[] messageSplit;
           			messageSplit = syslogString.split(SOURCE_ADDRESS);
           			if (messageSplit.length == 2) {
           				messageLog.setSourceAddress(InetAddressUtils.addr(messageSplit[1]));
           			    message.setBytes(ByteBuffer.wrap(messageSplit[0].getBytes()));
           			}
           		}
                   setMinionTimeStamp(message.getTimestamp());
                LOG.debug("Converting syslog message into event.");
                ConvertToEvent re = new ConvertToEvent(
                        messageLog.getSystemId(),
                        messageLog.getLocation(),
                        messageLog.getSourceAddress(),
                        messageLog.getSourcePort(),
                        // Decode the packet content as ASCII
                        // TODO: Support more character encodings?
                        StandardCharsets.US_ASCII.decode(message.getBytes()).toString(),
                        syslogdConfig,
                        parse(message.getBytes()),messageLog,getMinionTimeStamp()
                    );
                events.addEvent(re.getEvent());
            } catch (final UnsupportedEncodingException e) {
                LOG.info("Failure to convert package", e);
            } catch (final MessageDiscardedException e) {
                LOG.info("Message discarded, returning without enqueueing event.", e);
            } catch (final Throwable e) {
                LOG.error("Unexpected exception while processing SyslogConnection", e);
            }
        }
        return elog;
    }

    private void broadcast(Log eventLog)  {
        if (LOG.isTraceEnabled())  {
            for (Event event : eventLog.getEvents().getEventCollection()) {
                LOG.trace("Processing a syslog to event dispatch", event.toString());
                String uuid = event.getUuid();
                LOG.trace("Event {");
                LOG.trace("  uuid  = {}", (uuid != null && uuid.length() > 0 ? uuid : "<not-set>"));
                LOG.trace("  uei   = {}", event.getUei());
                LOG.trace("  src   = {}", event.getSource());
                LOG.trace("  iface = {}", event.getInterface());
                LOG.trace("  time  = {}", event.getTime());
                LOG.trace("  Msg   = {}", event.getLogmsg().getContent());
                LOG.trace("  Dst   = {}", event.getLogmsg().getDest());
                List<Parm> parms = (event.getParmCollection() == null ? null : event.getParmCollection());
                if (parms != null) {
                    LOG.trace("  parms {");
                    for (Parm parm : parms) {
                        if ((parm.getParmName() != null)
                                && (parm.getValue().getContent() != null)) {
                            LOG.trace("    ({}, {})", parm.getParmName().trim(), parm.getValue().getContent().trim());
                        }
                    }
                    LOG.trace("  }");
                }
                LOG.trace("}");
            }
        }
        eventForwarder.sendNowSync(eventLog);

        if (syslogdConfig.getNewSuspectOnMessage()) {
            eventLog.getEvents().getEventCollection().stream()
                .filter(e -> !e.hasNodeid())
                .forEach(e -> {
                    LOG.trace("Syslogd: Found a new suspect {}", e.getInterface());
                    sendNewSuspectEvent(localAddr, e.getInterface(), e.getDistPoller());
                });
        }
    }

    private void sendNewSuspectEvent(String localAddr, String trapInterface, String distPoller) {
        EventBuilder bldr = new EventBuilder(EventConstants.NEW_SUSPECT_INTERFACE_EVENT_UEI, "syslogd");
        bldr.setInterface(addr(trapInterface));
        bldr.setHost(localAddr);
        bldr.setDistPoller(distPoller);
        eventForwarder.sendNow(bldr.getEvent());
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        // Automatically register the consumer on initialization
        messageConsumerManager.registerConsumer(this);
    }

    public void setEventForwarder(EventForwarder eventForwarder) {
        this.eventForwarder = eventForwarder;
    }

    public void setMessageConsumerManager(MessageConsumerManager messageConsumerManager) {
        this.messageConsumerManager = messageConsumerManager;
    }

    public void setSyslogdConfig(SyslogdConfig syslogdConfig) {
        this.syslogdConfig = syslogdConfig;
    }

    public void setDistPollerDao(DistPollerDao distPollerDao) {
        this.distPollerDao = distPollerDao;
    }
    
    /**
     * This method will parse the message against the grok patterns
     * @param messageBytes 
     *  
     * @return
     *  Parameter list
     */
        public static Map<String, String> parse(ByteBuffer messageBytes) {
                String grokPattern;
                Map<String, String> paramsMap = new HashMap<String,String>();
                if (null == getGrokPatternsList() || getGrokPatternsList().isEmpty()) {
                        LOG.error("No Grok Pattern has been defined");
                        return null;
                }
                for (int i = 0; i < getGrokPatternsList().size(); i++) {
                        grokPattern = getGrokPatternsList().get(i);
                        BufferParserFactory grokFactory = GrokParserFactory
                                        .parseGrok(grokPattern);
                        ByteBuffer incoming = ByteBuffer.wrap(messageBytes.array());
                        try {
                        		 paramsMap = loadParamsMap(grokFactory
                                        .parse(incoming.asReadOnlyBuffer(), m_executor).get()
                                        .getParmCollection());
							checkForHostName(paramsMap);
							checkForProcessName(paramsMap);
							paramsMap.put("Date", getDateString(paramsMap).toString());
                        		LOG.debug("Grok Pattern "+grokPattern+" matches syslog message.");
                                return paramsMap;
                        } catch (InterruptedException | ExecutionException e) {
                               // LOG.debug("Parse Exception occured !!!Grok Pattern "+grokPattern+" didn't match");
                                continue;
                        }
                }
                return null;

        }
        
		public static Map<String, String> loadParamsMap(List<Parm> paramsList) {
                return paramsList.stream().collect(
                                Collectors.toMap(Parm::getParmName, param -> param.getValue()
                                                .getContent(), (paramKey1, paramKey2) -> paramKey2));
        }
        
        
		/**
		 * This method will read syslogd grok properties file and return grok pattern
		 * list
		 * 
		 * @param syslogdConfigdFile
		 * @return
		 * @throws IOException
		 */
		public static List<String> readPropertiesInOrderFrom(File syslogdConfigdFile) throws IOException {

			Set<String> grookSet = new LinkedHashSet<String>();
			if (syslogdConfigdFile.exists() && syslogdConfigdFile.isFile()) {
				try (Reader reader = new FileReader(syslogdConfigdFile)) {
					new BufferedReader(reader).lines().forEach(pattern -> {
						// Ignore comments and blank lines
						if (pattern == null || pattern.trim().length() == 0 || pattern.trim().startsWith("#")) {
							return;
						}
						grookSet.add(pattern);
					});

					reader.close();
				}
			}
			grokPatternsList = new ArrayList<String>(grookSet);
			return grokPatternsList;

		}
		
		private static void checkForProcessName(Map<String, String> paramsMap) throws InterruptedException {
			if (paramsMap.get(PROCESS_NAME) != null
					&& (paramsMap.get(PROCESS_NAME).isEmpty()||returnForHostValue(paramsMap.get(PROCESS_NAME))||(paramsMap.get(PROCESS_NAME).contains("[") && paramsMap.get(PROCESS_NAME).contains("]"))
							|| (Arrays.asList(OFFSETS).contains(paramsMap.get(PROCESS_NAME))
									||paramsMap.get(PROCESS_NAME).contains(":") 
									    || (paramsMap.get(PROCESS_NAME).length() == 3
											&& paramsMap.get(PROCESS_NAME).startsWith("T"))))) {
				throw new InterruptedException();
			}

		}
		
		private static void checkForHostName(Map<String, String> paramsMap) throws InterruptedException {
			if (paramsMap.get(HOSTNAME) != null && !paramsMap.get(HOSTNAME).isEmpty()) {
				String hostname = paramsMap.get(HOSTNAME);
				if(!returnForHostValue(hostname))
					throw new InterruptedException();
			}

		}
		
		private static boolean returnForHostValue(String hostName)
		{
			if (m_hostname.matcher(hostName).matches()) {
				return true;
			} else if (m_ipaddressPattern.matcher(hostName).matches()) {
				return true;
			} else if (hostName.trim().equalsIgnoreCase(LOCALHOST)) {
				return true;
			}
			return false;
		}

		public static String getDateString(Map<String, String> dateParams) throws InterruptedException {
			StringBuilder dateBuilder = new StringBuilder();
			Long milliSeconds;
			String hour, seconds, minute, millisecond, day, month, year, timeOffsets, DATE_SEPERATOR, WHITE_SPACE = " ",
					timeZone, TIME_SEPERATOR = ":",date;
			try {
				if (dateParams.get(DATE) != null) {
					date = dateParams.get(DATE);
					if (date.contains(OFFSET_DELIMITER)) {
						throw new InterruptedException();
					}
					if (date.contains(".")) {
						int startIndex = date.indexOf(".");
						int endIndex = startIndex + 6;
						String subString = date.substring(startIndex, endIndex + 1);
						date = date.replace(subString, "");
					}
					return date.trim();
				}

			if (dateParams.get(CalenderConstant.year.toString()) == null && dateParams.get(CalenderConstant.day.toString()) == null
						&& dateParams.get(CalenderConstant.month.toString()) == null && dateParams.get(CalenderConstant.hours.toString()) == null
						&& dateParams.get(CalenderConstant.minutes.toString()) == null && dateParams.get(CalenderConstant.seconds.toString()) == null
						&& dateParams.get(CalenderConstant.milliseconds.toString()) == null && dateParams.get(CalenderConstant.timeOffsets.toString()) == null
						&& dateParams.get(CalenderConstant.timeZone.toString()) == null) {
					dateBuilder = new StringBuilder();
					return dateBuilder.append(getMinionTimeStamp()).toString();
				}
				year = getStringTokenValue(dateParams, CalenderConstant.year.toString(), String.valueOf(Calendar.getInstance().get(Calendar.YEAR)));
				day = getStringTokenValue(dateParams, CalenderConstant.day.toString(),
						String.valueOf(Calendar.getInstance().get(Calendar.DAY_OF_MONTH)));
				month = getStringTokenValue(dateParams, CalenderConstant.month.toString(),
						String.valueOf(Calendar.getInstance().get(Calendar.MONTH)));
				hour = getStringTokenValue(dateParams, CalenderConstant.hours.toString(), String.valueOf(Calendar.getInstance().get(Calendar.HOUR_OF_DAY)));
				minute = getStringTokenValue(dateParams, CalenderConstant.minutes.toString(),
						String.valueOf(Calendar.getInstance().get(Calendar.MINUTE)));
				seconds = getStringTokenValue(dateParams, CalenderConstant.seconds.toString(),
						String.valueOf(Calendar.getInstance().get(Calendar.SECOND)));
				millisecond = getStringTokenValue(dateParams, CalenderConstant.milliseconds.toString(), "");
				timeOffsets = getStringTokenValue(dateParams, CalenderConstant.timeOffsets.toString(), "");
				timeZone = getStringTokenValue(dateParams, CalenderConstant.timeZone.toString(), "");

				milliSeconds = 0L;
				if (!millisecond.isEmpty() && !millisecond.contains(OFFSET_DELIMITER)) {
					milliSeconds = Long.parseLong(millisecond);
				} else if (!millisecond.isEmpty() && millisecond.contains(OFFSET_DELIMITER)) {
					milliSeconds = Long.parseLong(millisecond.replace(OFFSET_DELIMITER, ""));
					timeZone = CalenderConstant.UTC.toString();
				}

				if (isInteger(month)) {
					DATE_SEPERATOR = "-";
				} else {
					DATE_SEPERATOR = " ";
				}

				dateBuilder.append(month);
				dateBuilder.append(DATE_SEPERATOR);
				dateBuilder.append(day);
				if (!year.isEmpty()) {
					dateBuilder.append(DATE_SEPERATOR);
					dateBuilder.append(year);
					dateBuilder.append(WHITE_SPACE);
				} else {
					dateBuilder.append(WHITE_SPACE);
				}
				dateBuilder.append(hour);
				dateBuilder.append(TIME_SEPERATOR);
				dateBuilder.append(minute);
				dateBuilder.append(TIME_SEPERATOR);
				dateBuilder.append(seconds);
				if (!timeOffsets.isEmpty())
					dateBuilder.append(timeOffsets);
				if (!timeZone.isEmpty()) {
					dateBuilder.append(WHITE_SPACE);
					dateBuilder.append(timeZone.replace(":", ""));
				}
				if (matchDateTimePattern(dateBuilder.toString())) {
					return dateBuilder.toString();
				}
			}
			catch (Exception e) {
				throw new InterruptedException();
			}
			throw new InterruptedException();
		}

		
		private static String getStringTokenValue(Map<String, String> params, String field, String isNullValue) {
			String value;

			if (null == params.get(field)) {
				value = isNullValue;
			} else if (params.get(field).equals("-")) {
				value = isNullValue;
			} else {

				value = params.get(field);
			}
			if (((field.equalsIgnoreCase(CalenderConstant.seconds.toString()) || field.equalsIgnoreCase(CalenderConstant.minutes.toString()) || field.equalsIgnoreCase(CalenderConstant.hours.toString())
					|| (field.equalsIgnoreCase(CalenderConstant.day.toString()) || (field.equalsIgnoreCase(CalenderConstant.month.toString()) && isInteger(value)))))
					&& value.length() == 1) {
				value = "0".concat(value);
			}
			return value.trim();
		}
		
		/*
		 * Method to pass and match date with formats "yyyy-MM-dd'T'HH:mm:ss'Z'"
		 */
		private static boolean matchDateTimePattern(String date) throws InterruptedException {
	
			for (int i = 0; i < datePatternList.size(); i++) {
				if (datePatternList.get(i).matcher(date).matches()) {
					return true;
				}
			}
			throw new InterruptedException();
		}

		public static boolean isInteger(String s) {
			try {
				Integer.parseInt(s);
			} catch (NumberFormatException e) {
				return false;
			} catch (NullPointerException e) {
				return false;
			}
			return true;
		}
		
		/**
		 * This method will read syslogd grok properties file and return grok pattern
		 * list
		 * @param propertiesFileName 
		 * 
		 * @param restConfigFile
		 * @return
		 * @throws IOException
		 */
		public static Map<String, String> readPropertiesInOrderFromToMap(File propertiesFileName) throws IOException {
			InputStream propertiesFileInputStream = new FileInputStream(propertiesFileName);
			Map<String, String> restConfigMap = new HashMap<String, String>();
			final Properties properties = new Properties();
			final BufferedReader reader = new BufferedReader(new InputStreamReader(propertiesFileInputStream));

			String bufferedReader = reader.readLine();

			while (bufferedReader != null) {
				final ByteArrayInputStream lineStream = new ByteArrayInputStream(bufferedReader.getBytes("ISO-8859-1"));
				properties.load(lineStream);

				final Enumeration<?> propertyNames = properties.<String>propertyNames();

				if (propertyNames.hasMoreElements()) {

					final String configurationKey = (String) propertyNames.nextElement();
					final String configurationValue = properties.getProperty(configurationKey);

					restConfigMap.put(configurationKey, configurationValue);
					properties.clear();
				}
				bufferedReader = reader.readLine();
			}
			reader.close();
			return restConfigMap;
		}

}
