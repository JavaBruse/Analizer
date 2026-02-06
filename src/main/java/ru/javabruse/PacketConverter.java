package ru.javabruse;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public class PacketConverter {
    public static PacketData convert(Packet packet) {
        PacketData data = new PacketData();
        data.setTimestamp(Instant.now());
        data.setLength(packet.length());

        // Основные заголовки
        extractNetworkLayer(data, packet);
        extractTransportLayer(data, packet);

        // Анализ приложения
        data.setApplication(detectApplication(data));

        // Дополнительные вычисления
        computeDerivedFields(data);

        // TLS анализ
        if (shouldAnalyzeTls(data)) {
            analyzeTls(data, packet);
        }

        return data;
    }

    private static void extractNetworkLayer(PacketData data, Packet packet) {
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            IpV4Packet.IpV4Header ipHeader = ip.getHeader();

            data.setSrcIp(ipHeader.getSrcAddr().getHostAddress());
            data.setDstIp(ipHeader.getDstAddr().getHostAddress());
            data.setProtocol(ipHeader.getProtocol().name());
            data.setTimeToLive(ipHeader.getTtlAsInt());
            data.setIsFragmented(ipHeader.getMoreFragmentFlag() || ipHeader.getFragmentOffset() > 0);

            // Проверка IP
            data.setIsPrivateIp(isPrivateIp(data.getSrcIp()) || isPrivateIp(data.getDstIp()));
            data.setIsLocalTraffic(isPrivateIp(data.getSrcIp()) && isPrivateIp(data.getDstIp()));
            data.setPacketDirection(determineDirection(data));
        }
    }

    private static void extractTransportLayer(PacketData data, Packet packet) {
        // TCP
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            TcpPacket.TcpHeader tcpHeader = tcp.getHeader();

            data.setSrcPort(tcpHeader.getSrcPort().valueAsInt() & 0xFFFF);
            data.setDstPort(tcpHeader.getDstPort().valueAsInt() & 0xFFFF);
            data.setTcpFlags(getTcpFlags(tcpHeader));
            data.setWindowSize(tcpHeader.getWindowAsInt());

            // TCP Options
            // extractTcpOptions(data, tcpHeader);

            // Шифрование по порту
            data.setIsEncrypted(isEncryptedPort(data.getDstPort()));
        }
        // UDP
        else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            UdpPacket.UdpHeader udpHeader = udp.getHeader();

            data.setSrcPort(udpHeader.getSrcPort().valueAsInt() & 0xFFFF);
            data.setDstPort(udpHeader.getDstPort().valueAsInt() & 0xFFFF);
            data.setIsEncrypted(isEncryptedPort(data.getDstPort()));
        }
        // ICMP и другие
        else if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            if (ip.getHeader().getProtocol() == IpNumber.ICMPV4) {
                data.setApplication("ICMP");
            }
        }
    }



    private static void analyzeTls(PacketData data, Packet packet) {
        if (!packet.contains(TcpPacket.class)) return;

        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp.getPayload() == null) return;

        byte[] payload = tcp.getPayload().getRawData();
        if (payload.length < 5 || payload[0] != 0x16) return; // Not TLS Handshake

        Map<String, Object> tlsData = parseTlsHandshake(payload);
        if (tlsData.isEmpty()) return;

        data.setIsTls(true);
        data.setTlsVersion((Integer) tlsData.get("version"));
        data.setSni((String) tlsData.get("sni"));
        data.setAlpn((String) tlsData.get("alpn"));
        data.setCipherSuites((List<Integer>) tlsData.get("ciphers"));
        data.setSupportedGroups((List<Integer>) tlsData.get("supported_groups"));
        data.setSupportedVersions((List<Integer>) tlsData.get("supported_versions"));
        data.setClientRandom((byte[]) tlsData.get("random"));

        // Вычисление JA4/JA4S (упрощённо)
        data.setJa4Hash(calculateSimpleJa4(payload));
    }

    private static Map<String, Object> parseTlsHandshake(byte[] payload) {
        Map<String, Object> tlsData = new HashMap<>();
        if (payload.length < 5 || payload[0] != 0x16) return tlsData;

        try {
            int ptr = 5; // После TLS Record Header (0x16 + версия + длина)

            // Проверяем Handshake Type (1 = ClientHello)
            if (ptr >= payload.length || payload[ptr] != 0x01) return tlsData;
            ptr++;

            // Длина ClientHello (3 байта)
            if (ptr + 2 >= payload.length) return tlsData;
            int clientHelloLen = ((payload[ptr] & 0xFF) << 16) |
                    ((payload[ptr+1] & 0xFF) << 8) |
                    (payload[ptr+2] & 0xFF);
            ptr += 3;

            // TLS Version (2 байта)
            if (ptr + 1 >= payload.length) return tlsData;
            tlsData.put("version", ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF));
            ptr += 2;

            // Random (32 байта)
            if (ptr + 32 > payload.length) return tlsData;
            tlsData.put("random", Arrays.copyOfRange(payload, ptr, ptr + 32));
            ptr += 32;

            // Session ID Length + пропускаем Session ID
            if (ptr >= payload.length) return tlsData;
            int sessionIdLen = payload[ptr] & 0xFF;
            ptr += 1 + sessionIdLen;

            // Cipher Suites Length + список
            if (ptr + 1 >= payload.length) return tlsData;
            int cipherSuitesLen = ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF);
            ptr += 2;

            if (ptr + cipherSuitesLen > payload.length) return tlsData;
            List<Integer> ciphers = new ArrayList<>();
            for (int i = 0; i < cipherSuitesLen / 2; i++) {
                int cipher = ((payload[ptr + i*2] & 0xFF) << 8) | (payload[ptr + i*2 + 1] & 0xFF);
                ciphers.add(cipher);
            }
            tlsData.put("ciphers", ciphers);
            ptr += cipherSuitesLen;

            // Compression Methods Length + пропускаем
            if (ptr >= payload.length) return tlsData;
            int compLen = payload[ptr] & 0xFF;
            ptr += 1 + compLen;

            // Extensions Length
            if (ptr + 1 >= payload.length) return tlsData;
            int extensionsLen = ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF);
            ptr += 2;

            int extensionsEnd = ptr + extensionsLen;
            if (extensionsEnd > payload.length) extensionsEnd = payload.length;

            // Парсим расширения
            while (ptr <= extensionsEnd - 4) {
                int extType = ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF);
                int extLen = ((payload[ptr+2] & 0xFF) << 8) | (payload[ptr+3] & 0xFF);
                ptr += 4;

                if (ptr + extLen > payload.length) break;

                switch (extType) {
                    case 0x0000: // server_name (SNI)
                        if (extLen > 9 && payload[ptr+2] == 0x00 && payload[ptr+3] == 0x00) {
                            int sniListLen = ((payload[ptr+4] & 0xFF) << 8) | (payload[ptr+5] & 0xFF);
                            if (sniListLen > 3 && payload[ptr+6] == 0x00) {
                                int sniLen = ((payload[ptr+7] & 0xFF) << 8) | (payload[ptr+8] & 0xFF);
                                if (sniLen > 0 && ptr + 9 + sniLen <= payload.length) {
                                    String sni = new String(payload, ptr + 9, sniLen, StandardCharsets.UTF_8);
                                    tlsData.put("sni", sni);
                                }
                            }
                        }
                        break;

                    case 0x000A: // supported_groups
                        if (extLen > 2) {
                            List<Integer> groups = new ArrayList<>();
                            int groupsLen = ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF);
                            int maxGroups = Math.min(groupsLen / 2, extLen / 2 - 1);
                            for (int i = 0; i < maxGroups; i++) {
                                int group = ((payload[ptr+2+i*2] & 0xFF) << 8) | (payload[ptr+3+i*2] & 0xFF);
                                groups.add(group);
                            }
                            tlsData.put("supported_groups", groups);
                        }
                        break;

                    case 0x0010: // application_layer_protocol_negotiation (ALPN)
                        if (extLen > 2) {
                            int alpnLen = ((payload[ptr] & 0xFF) << 8) | (payload[ptr+1] & 0xFF);
                            int alpnPtr = ptr + 2;
                            int end = alpnPtr + alpnLen;
                            while (alpnPtr < end && alpnPtr < payload.length) {
                                int protoLen = payload[alpnPtr] & 0xFF;
                                if (protoLen > 0 && alpnPtr + 1 + protoLen <= payload.length) {
                                    String proto = new String(payload, alpnPtr + 1, protoLen, StandardCharsets.UTF_8);
                                    tlsData.put("alpn", proto);
                                    break; // Берём первый протокол
                                }
                                alpnPtr += 1 + protoLen;
                            }
                        }
                        break;

                    case 0x002B: // supported_versions
                        if (extLen > 1) {
                            List<Integer> versions = new ArrayList<>();
                            int verLen = payload[ptr] & 0xFF;
                            int maxVersions = Math.min(verLen / 2, (extLen - 1) / 2);
                            for (int i = 0; i < maxVersions; i++) {
                                int ver = ((payload[ptr+1+i*2] & 0xFF) << 8) | (payload[ptr+2+i*2] & 0xFF);
                                versions.add(ver);
                            }
                            tlsData.put("supported_versions", versions);
                        }
                        break;
                }
                ptr += extLen;
            }
        } catch (Exception e) {
            // Пропускаем ошибки парсинга
        }

        return tlsData;
    }

    private static String calculateSimpleJa4(byte[] payload) {
        StringBuilder ja4 = new StringBuilder("t");

        if (payload.length > 2) {
            // TLS version
            ja4.append(String.format("%02x%02x", payload[1], payload[2]));
        }

        ja4.append("_c");
        // Первые 3 cipher suites
        if (payload.length > 44) {
            for (int i = 0; i < 3; i++) {
                int idx = 44 + i * 2;
                if (idx + 1 < payload.length) {
                    ja4.append(String.format("%02x%02x", payload[idx], payload[idx+1]));
                }
            }
        }

        return ja4.toString();
    }

    private static String getTcpFlags(TcpPacket.TcpHeader tcpHeader) {
        StringBuilder flags = new StringBuilder();
        if (tcpHeader.getSyn()) flags.append("S");
        if (tcpHeader.getAck()) flags.append("A");
        if (tcpHeader.getFin()) flags.append("F");
        if (tcpHeader.getRst()) flags.append("R");
        if (tcpHeader.getPsh()) flags.append("P");
        if (tcpHeader.getUrg()) flags.append("U");
        return flags.toString();
    }

    private static boolean isEncryptedPort(int port) {
        return port == 443 || port == 8443 || port == 993 || port == 995 || port == 465;
    }

    private static boolean isPrivateIp(String ip) {
        return ip.startsWith("10.") ||
                ip.startsWith("192.168.") ||
                (ip.startsWith("172.") && ip.matches("172\\.(1[6-9]|2[0-9]|3[0-1])\\..*"));
    }

    private static String determineDirection(PacketData data) {
        if (data.getSrcIp() == null || data.getDstIp() == null) return "unknown";

        boolean srcPrivate = isPrivateIp(data.getSrcIp());
        boolean dstPrivate = isPrivateIp(data.getDstIp());

        if (srcPrivate && !dstPrivate) return "outbound";
        if (!srcPrivate && dstPrivate) return "inbound";
        if (srcPrivate && dstPrivate) return "internal";
        return "external";
    }

    private static String detectApplication(PacketData data) {
        if (data.getDstPort() == null) return "unknown";

        // Если есть TLS данные
        if (Boolean.TRUE.equals(data.getIsTls())) {
            if (data.getSni() != null) return "TLS/" + data.getSni();
            if (data.getAlpn() != null) return "TLS/" + data.getAlpn();
            return "TLS/encrypted";
        }

        // По порту
        switch (data.getDstPort()) {
            case 80: case 8080: return "HTTP";
            case 443: case 8443: return "HTTPS";
            case 53: return "DNS";
            case 22: return "SSH";
            case 25: case 587: return "SMTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 3306: return "MySQL";
            case 5432: return "PostgreSQL";
            case 6379: return "Redis";
            case 27017: return "MongoDB";
            case 9200: return "Elasticsearch";
            case 5060: case 5061: return "SIP";
            case 1194: return "OpenVPN";
            case 5222: case 5223: return "XMPP";
            default:
                if (data.getDstPort() >= 49152) return "ephemeral";
                return "port_" + data.getDstPort();
        }
    }

    private static boolean shouldAnalyzeTls(PacketData data) {
        return data.getDstPort() != null &&
                (data.getDstPort() == 443 || data.getDstPort() == 8443 ||
                        data.getDstPort() == 993 || data.getDstPort() == 995);
    }

    private static void computeDerivedFields(PacketData data) {
        // GEO и ASN будут добавлены позже через внешние сервисы
        // Пока заглушки
        data.setGeoCountry("unknown");
        data.setGeoCity("unknown");
        data.setAsn("unknown");
        data.setPacketsPerSecond(0.0);
    }
}