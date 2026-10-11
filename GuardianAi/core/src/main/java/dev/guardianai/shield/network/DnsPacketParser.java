package dev.guardianai.shield.network;

import java.util.Arrays;

/**
 * Lightweight, zero-dependency IPv4 UDP DNS packet parser.
 * Designed for local on-device packet inspection without memory allocations.
 */
public class DnsPacketParser {

    public static class ParsedDnsQuery {
        public final byte[] sourceIp;
        public final byte[] destinationIp;
        public final int sourcePort;
        public final int destinationPort;
        public final int transactionId;
        public final int flags;
        public final String qName;
        public final int qType;
        public final int qClass;
        public final byte[] rawDnsPayload;
        public final byte[] rawIpHeader;
        public final int ipHeaderLength;

        public ParsedDnsQuery(
                byte[] sourceIp,
                byte[] destinationIp,
                int sourcePort,
                int destinationPort,
                int transactionId,
                int flags,
                String qName,
                int qType,
                int qClass,
                byte[] rawDnsPayload,
                byte[] rawIpHeader,
                int ipHeaderLength
        ) {
            this.sourceIp = sourceIp;
            this.destinationIp = destinationIp;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.transactionId = transactionId;
            this.flags = flags;
            this.qName = qName;
            this.qType = qType;
            this.qClass = qClass;
            this.rawDnsPayload = rawDnsPayload;
            this.rawIpHeader = rawIpHeader;
            this.ipHeaderLength = ipHeaderLength;
        }

        public boolean isStandardQuery() {
            // QR flag is bit 15 (0x8000). 0 = Query, 1 = Response.
            return (flags & 0x8000) == 0;
        }
    }

    /**
     * Parses a raw IPv4 packet from the TUN buffer.
     * Returns null safely if the packet is malformed, truncated, or not a UDP DNS packet.
     */
    public static ParsedDnsQuery parse(byte[] buffer, int length) {
        if (buffer == null || length < 28) { // Minimum 20 bytes IP + 8 bytes UDP
            return null;
        }

        // Verify IPv4
        int version = (buffer[0] >> 4) & 0x0F;
        if (version != 4) {
            return null;
        }

        // IP Header Length
        int ihl = (buffer[0] & 0x0F) * 4;
        if (ihl < 20 || ihl + 8 > length) {
            return null;
        }

        // Protocol: 17 = UDP
        int protocol = buffer[9] & 0xFF;
        if (protocol != 17) {
            return null;
        }

        // Extract Source and Destination IPs
        byte[] srcIp = Arrays.copyOfRange(buffer, 12, 16);
        byte[] dstIp = Arrays.copyOfRange(buffer, 16, 20);

        // UDP Header
        int udpOffset = ihl;
        int srcPort = ((buffer[udpOffset] & 0xFF) << 8) | (buffer[udpOffset + 1] & 0xFF);
        int dstPort = ((buffer[udpOffset + 2] & 0xFF) << 8) | (buffer[udpOffset + 3] & 0xFF);
        int udpLen = ((buffer[udpOffset + 4] & 0xFF) << 8) | (buffer[udpOffset + 5] & 0xFF);

        if (udpLen < 8 || udpOffset + udpLen > length) {
            return null;
        }

        int dnsOffset = udpOffset + 8;
        int dnsPayloadLen = udpLen - 8;
        if (dnsPayloadLen < 12) { // DNS header is minimum 12 bytes
            return null;
        }

        // DNS Header
        int txId = ((buffer[dnsOffset] & 0xFF) << 8) | (buffer[dnsOffset + 1] & 0xFF);
        int flags = ((buffer[dnsOffset + 2] & 0xFF) << 8) | (buffer[dnsOffset + 3] & 0xFF);
        int qdCount = ((buffer[dnsOffset + 4] & 0xFF) << 8) | (buffer[dnsOffset + 5] & 0xFF);

        if (qdCount < 1) {
            return null;
        }

        // Parse QNAME
        StringBuilder domainBuilder = new StringBuilder();
        int pos = dnsOffset + 12;
        int maxPos = dnsOffset + dnsPayloadLen;

        while (pos < maxPos) {
            int labelLen = buffer[pos] & 0xFF;
            if (labelLen == 0) {
                pos++;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                // Compression pointer
                pos += 2;
                break;
            }
            pos++;
            if (pos + labelLen > maxPos) {
                return null; // Malformed QNAME exceeds payload bounds
            }
            if (domainBuilder.length() > 0) {
                domainBuilder.append('.');
            }
            for (int i = 0; i < labelLen; i++) {
                char c = (char) (buffer[pos + i] & 0xFF);
                domainBuilder.append(Character.toLowerCase(c));
            }
            pos += labelLen;
        }

        if (pos + 4 > maxPos) {
            return null; // Truncated question section (missing QTYPE/QCLASS)
        }

        int qType = ((buffer[pos] & 0xFF) << 8) | (buffer[pos + 1] & 0xFF);
        int qClass = ((buffer[pos + 2] & 0xFF) << 8) | (buffer[pos + 3] & 0xFF);

        byte[] rawDns = Arrays.copyOfRange(buffer, dnsOffset, dnsOffset + dnsPayloadLen);
        byte[] rawIpHdr = Arrays.copyOfRange(buffer, 0, ihl);

        return new ParsedDnsQuery(
                srcIp,
                dstIp,
                srcPort,
                dstPort,
                txId,
                flags,
                domainBuilder.toString(),
                qType,
                qClass,
                rawDns,
                rawIpHdr,
                ihl
        );
    }
}
