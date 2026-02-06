package ru.javabruse;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Main {
    public static void main(String[] args) throws Exception {
        String interfaceName = args.length > 0 ? args[0] : "any";

        // Автоопределение интерфейса
        PcapNetworkInterface nif = "any".equals(interfaceName)
                ? getAnyInterface()
                : Pcaps.getDevByName(interfaceName);

        if (nif == null) {
            log.error("Интерфейс не найден. Доступные:");
            Pcaps.findAllDevs().forEach(dev ->
                    log.info("  " + dev.getName() + " - " + dev.getDescription()));
            return;
        }

        log.info("Захват на: " + nif.getName());

        PcapHandle handle = nif.openLive(65536,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100);

        handle.loop(-1, (Packet packet) -> {
            PacketData data = PacketConverter.convert(packet);
            try {
                if (data.getDstIp().equals("172.16.1.33") || data.getSrcIp().equals("172.16.1.33")) {
                } else {
                    log.info(data.toString());
                }
            } catch (NullPointerException e){
                log.info(data.toString());
            }
        });
    }

    private static PcapNetworkInterface getAnyInterface() throws PcapNativeException {
        return Pcaps.findAllDevs().stream()
                .filter(dev -> !dev.isLoopBack())
                .findFirst()
                .orElse(null);
    }
}