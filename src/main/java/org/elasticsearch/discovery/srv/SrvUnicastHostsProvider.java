/*
 * Copyright (c) 2015 Grant Rodgers.
 * Portions copyright (c) 2015 Crate.IO.
 *
 *     Permission is hereby granted, free of charge, to any person obtaining
 *     a copy of this software and associated documentation files (the "Software"),
 *     to deal in the Software without restriction, including without limitation
 *     the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *     and/or sell copies of the Software, and to permit persons to whom the Software
 *     is furnished to do so, subject to the following conditions:
 *
 *     The above copyright notice and this permission notice shall be included in
 *     all copies or substantial portions of the Software.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *     EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *     OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *     IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *     CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *     TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
 *     OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.elasticsearch.discovery.srv;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;

import org.elasticsearch.Version;
import org.elasticsearch.cluster.node.DiscoveryNode;
import org.elasticsearch.common.Nullable;
import org.elasticsearch.common.base.Joiner;
import org.elasticsearch.common.collect.Lists;
import org.elasticsearch.common.component.AbstractComponent;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.discovery.zen.ping.unicast.UnicastHostsProvider;
import org.elasticsearch.transport.TransportService;
import org.xbill.DNS.*;

/**
 *
 */
public class SrvUnicastHostsProvider extends AbstractComponent implements UnicastHostsProvider {

    public static final String DISCOVERY_SRV_QUERY = "discovery.srv.query";
    public static final String DISCOVERY_SRV_SERVERS = "discovery.srv.servers";

    public static final String DISCOVERY_SRV_CONSULPOSTFIX = "discovery.srv.consulpostfix";

    public static final String DISCOVERY_SRV_PROTOCOL = "discovery.srv.protocol";

    private final TransportService transportService;

    private final Version version;

    private final String query;
    private final Resolver resolver;

    @Inject
    public SrvUnicastHostsProvider(Settings settings, TransportService transportService, Version version) {
        super(settings);
        this.transportService = transportService;
        this.version = version;

        this.query = settings.get(DISCOVERY_SRV_QUERY);
        this.resolver = buildResolver(settings);
    }

    @Nullable
    private Resolver buildResolver(Settings settings) {
        String[] addresses = settings.getAsArray(DISCOVERY_SRV_SERVERS);
        // Use tcp by default since it retrieves all records
        String protocol = settings.get(DISCOVERY_SRV_PROTOCOL, "tcp");

        List<Resolver> resolvers = Lists.newArrayList();

        Resolver parent_resolver = null;

        for (String address : addresses) {
            String host = null;
            int port = -1;
            String[] parts = address.split(":");
            if (parts.length > 0) {
                host = parts[0];
                if (parts.length > 1) {
                    try {
                        port = Integer.valueOf(parts[1]);
                    } catch (Exception e) {
                        logger.info("Resolver port '{}' is not an integer. Using default port 53", parts[1]);
                    }
                }

            }

            try {
                logger.info("Trying to resolve '{}'", host);
                Resolver resolver = new SimpleResolver(host);
                if (port > 0) {
                    resolver.setPort(port);
                }
                resolvers.add(resolver);
            } catch (UnknownHostException e) {
                logger.info("Could not create resolver for '{}'", address, e);
            }
        }

        if (resolvers.size() > 0) {
            try {
                parent_resolver = new ExtendedResolver(resolvers.toArray(new Resolver[resolvers.size()]));

                if (isTCP(protocol)) {
                    parent_resolver.setTCP(true);
                }
            } catch (UnknownHostException e) {
                logger.info("Could not create resolver. Using default resolver.", e);
            }
        } else {
            throw new RuntimeException("Unable to find resolvers");
        }
        logger.info("Trying to discover hosts with a list of {} resolvers", resolvers.size());
        return parent_resolver;
    }

    protected boolean isTCP(String protocol) {
        return "tcp".equals(protocol);
    }

    public List<DiscoveryNode> buildDynamicNodes() {
        logger.info("Entering buildDynamicNodes");
        List<DiscoveryNode> discoNodes = Lists.newArrayList();
        if (query == null) {
            logger.error("DNS query must not be null. Please set '{}'", DISCOVERY_SRV_QUERY);
            return discoNodes;
        }
        try {
            Record[] records = lookupRecords();
            logger.info("Found the following records: ", Joiner.on(", ").join(records));
            List<Record> filteredRecords = filterOutOwnRecord(records);
            logger.info("Building dynamic unicast discovery nodes...");
            if (filteredRecords == null || filteredRecords.size() == 0) {
                logger.warn("No nodes found");
            } else {
                discoNodes = parseRecords(filteredRecords);
            }
        } catch (TextParseException e) {
            logger.error("Unable to parse DNS query '{}'", query);
            logger.error("DNS lookup exception:", e);
        }
        logger.info("Using dynamic discovery nodes {}", discoNodes);
        return discoNodes;
    }

    protected boolean isLocalIP(String ip) {
        Enumeration e = null;
        try {
            e = NetworkInterface.getNetworkInterfaces();
        } catch (SocketException e1) {
            logger.error(e1.toString());
        }
        while (e.hasMoreElements()) {
            NetworkInterface n = (NetworkInterface) e.nextElement();
            Enumeration ee = n.getInetAddresses();
            while (ee.hasMoreElements()) {
                InetAddress i = (InetAddress) ee.nextElement();
                logger.info("Local interface address: " + i.getHostAddress());
                if (i.getHostAddress().equals((ip))) {
                    logger.info("Filtered out interface address " + ip + " because it was an local interface.");
                    return true;
                }
            }
        }
        return false;
    }

    protected List<Record> filterOutOwnRecord(Record[] records) {
        List<Record> discoNodes = Lists.newArrayList();
        logger.info("Trying to filter out localhost records from: ", Joiner.on(", ").join(discoNodes));
        for (Record record : records) {
            SRVRecord srv = (SRVRecord) record;

            String hostname = srv.getTarget().toString().replaceFirst("\\.$", "");

            if (!settings.get(DISCOVERY_SRV_CONSULPOSTFIX, "").isEmpty()) {
                hostname = hostname.replace(settings.get(DISCOVERY_SRV_CONSULPOSTFIX), "");
            }
            try {
                InetAddress address = InetAddress.getByName(hostname);
                logger.info("Resolved {} to {}", hostname, address.getHostAddress());
                if (!isLocalIP(address.getHostAddress())) {
                    discoNodes.add(record);
                }
            } catch (UnknownHostException e) {
                logger.error(e.toString());
            }
        }

        return discoNodes;
    }

    private Record[] lookupRecords() throws TextParseException {
        logger.info("lookupRecords: trying to find {}", query);
        Lookup lookup = new Lookup(query, Type.SRV);
        if (this.resolver != null) {
            lookup.setResolver(this.resolver);
        }
        Record[] records = lookup.run();
        if(records == null) {
            records = new Record[]{};
        }
        logger.info("lookupRecords found: {}", records);
        return records;
    }

    protected List<DiscoveryNode> parseRecords(List<Record> records) {
        List<DiscoveryNode> discoNodes = Lists.newArrayList();
        for (Record record : records) {
            SRVRecord srv = (SRVRecord) record;

            String hostname = srv.getTarget().toString().replaceFirst("\\.$", "");
            if (!settings.get(DISCOVERY_SRV_CONSULPOSTFIX).isEmpty()) {
                logger.info("Removing consul post fix from name '{}'", hostname);
                hostname = hostname.replace(settings.get(DISCOVERY_SRV_CONSULPOSTFIX), "");
            }
            int port = srv.getPort();
            String address = hostname + ":" + port;

            try {
                TransportAddress[] addresses = transportService.addressesFromString(address);
                logger.info("adding {}, transport_address {}", address, addresses[0]);
                discoNodes.add(new DiscoveryNode("#srv-" + address, addresses[0], version));
            } catch (Exception e) {
                logger.info("failed to add {}, address {}", e, address);
            }
        }
        return discoNodes;
    }
}
