package ru.javabruse;

import lombok.Data;

import java.time.Instant;

@Data
public class PacketData {
    private Instant timestamp;    // Когда поймали пакет, например: "2024-01-15T14:30:25.123456Z"
    private String srcIp;         // IP отправителя, например: "192.168.1.100"
    private Integer srcPort;      // Порт отправителя, например: 54321 (null если нет порта)
    private String dstIp;         // IP получателя, например: "8.8.8.8"
    private Integer dstPort;      // Порт получателя, например: 443 (null если нет порта)
    private String protocol;      // Протокол: "TCP", "UDP", "ICMP", например: "TCP"
    private Integer length;       // Размер пакета в байтах, например: 1500
    private String application;   // Приложение по порту, например: "HTTPS", "DNS", "SSH"
    private Boolean isEncrypted;  // Шифрованный ли трафик (true для портов 443, 993 и т.д.)
    private String tcpFlags;      // Флаги TCP: "SA" (SYN+ACK), "F" (FIN), например: "SA"

    @Override
    public String toString() {
        return "PacketData{" +
                "timestamp=" + timestamp +
                ", srcIp='" + srcIp + '\'' +
                ", srcPort=" + srcPort +
                ", dstIp='" + dstIp + '\'' +
                ", dstPort=" + dstPort +
                ", protocol='" + protocol + '\'' +
                ", length=" + length +
                ", application='" + application + '\'' +
                ", isEncrypted=" + isEncrypted +
                ", tcpFlags='" + tcpFlags + '\'' +
                '}';
    }
}
