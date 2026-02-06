package ru.javabruse;

import lombok.Data;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

@Data
public class PacketData {
    // Базовые метаданные
    private Instant timestamp;    // Когда поймали пакет
    private String srcIp;         // IP отправителя
    private Integer srcPort;      // Порт отправителя (0-65535)
    private String dstIp;         // IP получателя
    private Integer dstPort;      // Порт получателя (0-65535)
    private String protocol;      // Протокол: "TCP", "UDP", "ICMP"
    private Integer length;       // Размер пакета в байтах
    private String application;   // Приложение по порту/анализу
    private Boolean isEncrypted;  // Шифрованный ли трафик
    private String tcpFlags;      // Флаги TCP: "SA", "F", "R", "PSH", etc

    // TLS/SSL данные (для портов 443, 8443, 993, 995)
    private Boolean isTls;           // TLS трафик
    private Integer tlsVersion;      // TLS version (0x0303=1.2, 0x0304=1.3)
    private String sni;              // Server Name Indication (домен)
    private String alpn;             // Application-Layer Protocol Negotiation
    private List<Integer> cipherSuites; // Список шифров из ClientHello
    private List<Integer> supportedGroups; // Elliptic curve groups
    private List<Integer> supportedVersions; // Поддерживаемые TLS версии
    private byte[] clientRandom;     // Client Random (32 bytes)
    private String ja4Hash;          // JA4/TLS fingerprint (будущий анализ)
    private String ja4sHash;         // JA4S/Server fingerprint

    // Дополнительные поля для анализа
    private Integer timeToLive;      // TTL из IP заголовка
    private Boolean isFragmented;    // Фрагментирован ли пакет
    private Integer windowSize;      // TCP window size
    private Integer mss;             // Maximum Segment Size (из TCP options)
    private Boolean hasSackPermitted;// TCP SACK разрешён
    private String geoCountry;       // Страна по IP (будущее)
    private String geoCity;          // Город по IP (будущее)
    private String asn;              // Autonomous System Number
    private Boolean isPrivateIp;     // Частный ли IP (10.x, 192.168.x, 172.16-31.x)
    private Boolean isLocalTraffic;  // Трафик внутри локальной сети
    private String packetDirection;  // "inbound", "outbound", "internal"
    private Double packetsPerSecond; // Расчётная частота (будущее)

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
                ", isTls=" + isTls +
                ", tlsVersion=" + tlsVersion +
                ", sni='" + sni + '\'' +
                ", alpn='" + alpn + '\'' +
                ", cipherSuites=" + cipherSuites +
                ", supportedGroups=" + supportedGroups +
                ", supportedVersions=" + supportedVersions +
                ", clientRandom=" + Arrays.toString(clientRandom) +
                ", ja4Hash='" + ja4Hash + '\'' +
                ", ja4sHash='" + ja4sHash + '\'' +
                ", timeToLive=" + timeToLive +
                ", isFragmented=" + isFragmented +
                ", windowSize=" + windowSize +
                ", mss=" + mss +
                ", hasSackPermitted=" + hasSackPermitted +
                ", geoCountry='" + geoCountry + '\'' +
                ", geoCity='" + geoCity + '\'' +
                ", asn='" + asn + '\'' +
                ", isPrivateIp=" + isPrivateIp +
                ", isLocalTraffic=" + isLocalTraffic +
                ", packetDirection='" + packetDirection + '\'' +
                ", packetsPerSecond=" + packetsPerSecond +
                '}';
    }
}