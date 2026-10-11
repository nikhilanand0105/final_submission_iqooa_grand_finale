package dev.saathi.shield.network;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Builds IPv4 UDP packets and DNS response messages for on-device network protection.
 */
public class DnsPacketBuilder {

    /**
     * Builds a DNS sinkhole response returning 0.0.0.0 for Type A queries,
     * or NXDOMAIN for other query types, wrapped in a valid IPv4 UDP packet.
     */
    public static byte[] buildSinkholeResponse(DnsPacketParser.ParsedDnsQuery query) {
        if (query == null) {
            return null;
        }

        byte[] dnsResponse = buildSinkholeDnsPayload(query);
        return wrapInIpUdpPacket(query.destinationIp, query.sourceIp, query.destinationPort, query.sourcePort, dnsResponse);
    }

    /**
     * Wraps an arbitrary upstream DNS response in an IPv4 UDP packet
     * addressed back to the client that originated the query.
     */
    public static byte[] buildForwardedResponse(
            DnsPacketParser.ParsedDnsQuery query,
            byte[] upstreamDnsPayload,
            int payloadLength
    ) {
        if (query == null || upstreamDnsPayload == null || payloadLength <= 0) {
            return null;
        }

        byte[] dnsResponse = Arrays.copyOf(upstreamDnsPayload, payloadLength);
        return wrapInIpUdpPacket(query.destinationIp, query.sourceIp, query.destinationPort, query.sourcePort, dnsResponse);
    }

    private static byte[] buildSinkholeDnsPayload(DnsPacketParser.ParsedDnsQuery query) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Transaction ID (2 bytes)
        baos.write((query.transactionId >> 8) & 0xFF);
        baos.write(query.transactionId & 0xFF);

        boolean isTypeA = (query.qType == 1);

        // Flags: 0x8180 (Response, Recursion Available, No Error) for A
        //        0x8183 (Response, Recursion Available, NXDOMAIN) for non-A
        int flags = isTypeA ? 0x8180 : 0x8183;
        baos.write((flags >> 8) & 0xFF);
        baos.write(flags & 0xFF);

        // QDCOUNT (1)
        baos.write(0x00);
        baos.write(0x01);

        // ANCOUNT (1 for A, 0 for NXDOMAIN)
        baos.write(0x00);
        baos.write(isTypeA ? 0x01 : 0x00);

        // NSCOUNT (0)
        baos.write(0x00);
        baos.write(0x00);

        // ARCOUNT (0)
        baos.write(0x00);
        baos.write(0x00);

        // Question section (copy from original DNS payload starting at byte 12)
        if (query.rawDnsPayload != null && query.rawDnsPayload.length > 12) {
            baos.write(query.rawDnsPayload, 12, query.rawDnsPayload.length - 12);
        }

        // Answer Section for Type A
        if (isTypeA) {
            // Pointer to QNAME at offset 12 (0xC00C)
            baos.write(0xC0);
            baos.write(0x0C);

            // Type A (0x0001)
            baos.write(0x00);
            baos.write(0x01);

            // Class IN (0x0001)
            baos.write(0x00);
            baos.write(0x01);

            // TTL (60 seconds = 0x0000003C)
            baos.write(0x00);
            baos.write(0x00);
            baos.write(0x00);
            baos.write(0x3C);

            // Data length (4 bytes for IPv4)
            baos.write(0x00);
            baos.write(0x04);

            // Address: 0.0.0.0 (Sinkhole)
            baos.write(0x00);
            baos.write(0x00);
            baos.write(0x00);
            baos.write(0x00);
        }

        return baos.toByteArray();
    }

    private static byte[] wrapInIpUdpPacket(
            byte[] srcIp,
            byte[] dstIp,
            int srcPort,
            int dstPort,
            byte[] dnsPayload
    ) {
        int ipHeaderLen = 20;
        int udpHeaderLen = 8;
        int totalLen = ipHeaderLen + udpHeaderLen + dnsPayload.length;

        byte[] packet = new byte[totalLen];

        // IPv4 Header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[1] = 0x00; // Type of service
        packet[2] = (byte) ((totalLen >> 8) & 0xFF);
        packet[3] = (byte) (totalLen & 0xFF);
        packet[4] = 0x00; // Identification
        packet[5] = 0x00;
        packet[6] = 0x40; // Flags: Don't Fragment
        packet[7] = 0x00;
        packet[8] = 0x40; // TTL: 64
        packet[9] = 17;   // Protocol: 17 (UDP)
        packet[10] = 0x00; // Checksum placeholder
        packet[11] = 0x00;

        // Source IP
        System.arraycopy(srcIp, 0, packet, 12, 4);
        // Destination IP
        System.arraycopy(dstIp, 0, packet, 16, 4);

        // Compute IP Header Checksum
        int ipChecksum = computeIpChecksum(packet, ipHeaderLen);
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);

        // UDP Header
        int udpOffset = ipHeaderLen;
        packet[udpOffset] = (byte) ((srcPort >> 8) & 0xFF);
        packet[udpOffset + 1] = (byte) (srcPort & 0xFF);
        packet[udpOffset + 2] = (byte) ((dstPort >> 8) & 0xFF);
        packet[udpOffset + 3] = (byte) (dstPort & 0xFF);

        int udpLen = udpHeaderLen + dnsPayload.length;
        packet[udpOffset + 4] = (byte) ((udpLen >> 8) & 0xFF);
        packet[udpOffset + 5] = (byte) (udpLen & 0xFF);
        packet[udpOffset + 6] = 0x00; // UDP Checksum: 0 (disabled in IPv4 UDP per RFC 768)
        packet[udpOffset + 7] = 0x00;

        // UDP Payload (DNS Message)
        System.arraycopy(dnsPayload, 0, packet, udpOffset + 8, dnsPayload.length);

        return packet;
    }

    public static int computeIpChecksum(byte[] header, int length) {
        int sum = 0;
        for (int i = 0; i < length; i += 2) {
            if (i == 10) continue; // Skip checksum field itself
            int word = ((header[i] & 0xFF) << 8) | (header[i + 1] & 0xFF);
            sum += word;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (~sum) & 0xFFFF;
    }
}
