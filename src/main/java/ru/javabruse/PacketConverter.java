package ru.javabruse;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.time.Instant;

public class PacketConverter {
    public static PacketData convert(Packet packet) {
        PacketData data = new PacketData();
        data.setTimestamp(Instant.now());
        data.setLength(packet.length());

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ip = packet.get(IpV4Packet.class);
            data.setSrcIp(ip.getHeader().getSrcAddr().getHostAddress());
            data.setDstIp(ip.getHeader().getDstAddr().getHostAddress());
            data.setProtocol(ip.getHeader().getProtocol().name());

            // Порт
            data.setSrcPort(getPort(packet, true));
            data.setDstPort(getPort(packet, false));

            // TCP флаги
            if (packet.contains(TcpPacket.class)) {
                TcpPacket.TcpHeader tcp = packet.get(TcpPacket.class).getHeader();
                data.setTcpFlags(getTcpFlags(tcp));
                data.setIsEncrypted(isEncrypted(tcp.getDstPort().value()));
            }

            // Приложение по порту
            data.setApplication(detectApplication(data.getDstPort()));
        }

        return data;
    }

    private static Integer getPort(Packet packet, boolean source) {
        try {
            if (packet.contains(TcpPacket.class)) {
                return source ?
                        packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt() :
                        packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt();
            } else if (packet.contains(UdpPacket.class)) {
                return source ?
                        packet.get(UdpPacket.class).getHeader().getSrcPort().valueAsInt() :
                        packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt();
            }
        } catch (Exception e) {}
        return null;
    }

    private static String getTcpFlags(TcpPacket.TcpHeader tcp) {
        StringBuilder flags = new StringBuilder();
        if (tcp.getSyn()) flags.append("S");
        if (tcp.getAck()) flags.append("A");
        if (tcp.getFin()) flags.append("F");
        if (tcp.getRst()) flags.append("R");
        if (tcp.getPsh()) flags.append("P");
        if (tcp.getUrg()) flags.append("U");
        return flags.toString();
    }

    private static Boolean isEncrypted(int port) {
        return port == 443 || port == 8443 || port == 993 || port == 995;
    }

    private static String detectApplication(Integer port) {
        if (port == null) return "unknown";
        switch (port) {
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
            default: return "port_" + port;
        }
    }
}
