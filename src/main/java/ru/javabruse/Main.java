package ru.javabruse;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

public class Main {
    public static void main(String[] args) throws Exception {
        String interfaceName = args.length > 0 ? args[0] : "any";

        // Автоопределение интерфейса
        PcapNetworkInterface nif = "any".equals(interfaceName)
                ? getAnyInterface()
                : Pcaps.getDevByName(interfaceName);

        if (nif == null) {
            System.err.println("Интерфейс не найден. Доступные:");
            Pcaps.findAllDevs().forEach(dev ->
                    System.err.println("  " + dev.getName() + " - " + dev.getDescription()));
            return;
        }

        System.out.println("Захват на: " + nif.getName());

        // Захват с фильтром (без ARP)
        PcapHandle handle = nif.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);
        handle.setFilter("not arp", BpfProgram.BpfCompileMode.OPTIMIZE);

        // Бесконечный захват
        handle.loop(-1, (Packet packet) -> {
            if (packet.contains(IpV4Packet.class)) {
                IpV4Packet ip = packet.get(IpV4Packet.class);
                System.out.printf("%s:%d -> %s:%d [%s] %d bytes\n",
                        ip.getHeader().getSrcAddr(),
                        getSrcPort(packet),
                        ip.getHeader().getDstAddr(),
                        getDstPort(packet),
                        ip.getHeader().getProtocol(),
                        packet.length()
                );
            }
        });
    }

    private static PcapNetworkInterface getAnyInterface() throws PcapNativeException {
        return Pcaps.findAllDevs().stream()
                .filter(dev -> !dev.isLoopBack())
                .findFirst()
                .orElse(null);
    }

    private static int getSrcPort(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class).getHeader().getSrcPort().value();
        } else if (packet.contains(UdpPacket.class)) {
            return packet.get(UdpPacket.class).getHeader().getSrcPort().value();
        }
        return 0;
    }

    private static int getDstPort(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class).getHeader().getDstPort().value();
        } else if (packet.contains(UdpPacket.class)) {
            return packet.get(UdpPacket.class).getHeader().getDstPort().value();
        }
        return 0;
    }
}