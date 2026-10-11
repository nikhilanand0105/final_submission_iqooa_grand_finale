package dev.guardianai.shield.network;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class DnsPacketTest {

    private byte[] createSampleDnsQuery(String domain, int qType) {
        // Construct IPv4 UDP DNS query
        int ipHeaderLen = 20;
        int udpHeaderLen = 8;

        // Build DNS payload
        byte[] dnsHeader = new byte[]{
                (byte) 0x12, (byte) 0x34, // Transaction ID
                (byte) 0x01, (byte) 0x00, // Standard query
                (byte) 0x00, (byte) 0x01, // QDCOUNT: 1
                (byte) 0x00, (byte) 0x00, // ANCOUNT: 0
                (byte) 0x00, (byte) 0x00, // NSCOUNT: 0
                (byte) 0x00, (byte) 0x00  // ARCOUNT: 0
        };

        String[] labels = domain.split("\\.");
        int qnameLen = 0;
        for (String label : labels) {
            qnameLen += 1 + label.length();
        }
        qnameLen += 1; // terminating zero

        byte[] question = new byte[qnameLen + 4];
        int pos = 0;
        for (String label : labels) {
            question[pos++] = (byte) label.length();
            for (char c : label.toCharArray()) {
                question[pos++] = (byte) c;
            }
        }
        question[pos++] = 0; // null terminator
        question[pos++] = (byte) ((qType >> 8) & 0xFF);
        question[pos++] = (byte) (qType & 0xFF);
        question[pos++] = 0x00; // Class IN
        question[pos++] = 0x01;

        int dnsPayloadLen = dnsHeader.length + question.length;
        int totalLen = ipHeaderLen + udpHeaderLen + dnsPayloadLen;

        byte[] packet = new byte[totalLen];
        packet[0] = 0x45;
        packet[2] = (byte) ((totalLen >> 8) & 0xFF);
        packet[3] = (byte) (totalLen & 0xFF);
        packet[8] = 64; // TTL
        packet[9] = 17; // UDP

        // Source IP: 10.200.0.2
        packet[12] = 10;
        packet[13] = (byte) 200;
        packet[14] = 0;
        packet[15] = 2;

        // Destination IP: 10.200.0.1
        packet[16] = 10;
        packet[17] = (byte) 200;
        packet[18] = 0;
        packet[19] = 1;

        // IP Checksum
        int checksum = DnsPacketBuilder.computeIpChecksum(packet, ipHeaderLen);
        packet[10] = (byte) ((checksum >> 8) & 0xFF);
        packet[11] = (byte) (checksum & 0xFF);

        // UDP Header
        int udpOffset = ipHeaderLen;
        packet[udpOffset] = 0x30;     // Src Port: 12345
        packet[udpOffset + 1] = 0x39;
        packet[udpOffset + 2] = 0x00; // Dst Port: 53
        packet[udpOffset + 3] = 0x35;
        int udpLen = udpHeaderLen + dnsPayloadLen;
        packet[udpOffset + 4] = (byte) ((udpLen >> 8) & 0xFF);
        packet[udpOffset + 5] = (byte) (udpLen & 0xFF);

        // Copy DNS
        System.arraycopy(dnsHeader, 0, packet, udpOffset + 8, dnsHeader.length);
        System.arraycopy(question, 0, packet, udpOffset + 8 + dnsHeader.length, question.length);

        return packet;
    }

    @Test
    public void testParseValidDnsQuery() {
        byte[] raw = createSampleDnsQuery("phishing-sbi-portal.xyz", 1);
        DnsPacketParser.ParsedDnsQuery query = DnsPacketParser.parse(raw, raw.length);

        assertNotNull(query);
        assertEquals("phishing-sbi-portal.xyz", query.qName);
        assertEquals(1, query.qType);
        assertEquals(0x1234, query.transactionId);
        assertEquals(12345, query.sourcePort);
        assertEquals(53, query.destinationPort);
        assertTrue(query.isStandardQuery());
    }

    @Test
    public void testParseMalformedPacketsSafely() {
        // Null or truncated
        assertNull(DnsPacketParser.parse(null, 0));
        assertNull(DnsPacketParser.parse(new byte[15], 15));

        // Non-IPv4
        byte[] nonIpv4 = new byte[40];
        nonIpv4[0] = 0x60; // IPv6
        assertNull(DnsPacketParser.parse(nonIpv4, 40));

        // Non-UDP (TCP = 6)
        byte[] tcpPacket = new byte[40];
        tcpPacket[0] = 0x45;
        tcpPacket[9] = 6;
        assertNull(DnsPacketParser.parse(tcpPacket, 40));

        // Corrupt QNAME exceeding bounds
        byte[] raw = createSampleDnsQuery("test.com", 1);
        // Corrupt length byte
        raw[20 + 8 + 12] = 100; // Label claims length 100 which exceeds payload
        assertNull(DnsPacketParser.parse(raw, raw.length));
    }

    @Test
    public void testBuildSinkholeResponse_TypeA() {
        byte[] raw = createSampleDnsQuery("malicious-c2-trojan.com", 1);
        DnsPacketParser.ParsedDnsQuery query = DnsPacketParser.parse(raw, raw.length);
        assertNotNull(query);

        byte[] responsePacket = DnsPacketBuilder.buildSinkholeResponse(query);
        assertNotNull(responsePacket);
        assertTrue(responsePacket.length > 28);

        // Verify response destination is client
        assertEquals(10, responsePacket[16]);
        assertEquals((byte) 200, responsePacket[17]);
        assertEquals(0, responsePacket[18]);
        assertEquals(2, responsePacket[19]);

        // Verify destination port matches query source port
        int dstPort = ((responsePacket[22] & 0xFF) << 8) | (responsePacket[23] & 0xFF);
        assertEquals(12345, dstPort);

        // Verify DNS flags in response: 0x8180 (No error)
        int dnsOffset = 28;
        int flags = ((responsePacket[dnsOffset + 2] & 0xFF) << 8) | (responsePacket[dnsOffset + 3] & 0xFF);
        assertEquals(0x8180, flags);

        // Verify Answer Count is 1
        int anCount = ((responsePacket[dnsOffset + 6] & 0xFF) << 8) | (responsePacket[dnsOffset + 7] & 0xFF);
        assertEquals(1, anCount);

        // Verify sinkhole address at end of packet is 0.0.0.0
        int len = responsePacket.length;
        assertEquals(0, responsePacket[len - 4]);
        assertEquals(0, responsePacket[len - 3]);
        assertEquals(0, responsePacket[len - 2]);
        assertEquals(0, responsePacket[len - 1]);
    }

    @Test
    public void testBuildSinkholeResponse_TypeAAAA_ReturnsNxDomain() {
        byte[] raw = createSampleDnsQuery("malicious-c2-trojan.com", 28); // Type AAAA
        DnsPacketParser.ParsedDnsQuery query = DnsPacketParser.parse(raw, raw.length);
        assertNotNull(query);

        byte[] responsePacket = DnsPacketBuilder.buildSinkholeResponse(query);
        assertNotNull(responsePacket);

        // Verify NXDOMAIN flag (0x8183)
        int dnsOffset = 28;
        int flags = ((responsePacket[dnsOffset + 2] & 0xFF) << 8) | (responsePacket[dnsOffset + 3] & 0xFF);
        assertEquals(0x8183, flags);

        // Verify Answer Count is 0
        int anCount = ((responsePacket[dnsOffset + 6] & 0xFF) << 8) | (responsePacket[dnsOffset + 7] & 0xFF);
        assertEquals(0, anCount);
    }

    @Test
    public void testIpChecksumCalculation() {
        byte[] header = new byte[20];
        header[0] = 0x45;
        header[2] = 0x00;
        header[3] = 0x3C;
        header[8] = 64;
        header[9] = 17;
        header[12] = 10;
        header[13] = (byte) 200;
        header[14] = 0;
        header[15] = 1;
        header[16] = 10;
        header[17] = (byte) 200;
        header[18] = 0;
        header[19] = 2;

        int cs = DnsPacketBuilder.computeIpChecksum(header, 20);
        assertTrue(cs > 0 && cs <= 0xFFFF);
    }
}
