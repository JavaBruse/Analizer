FROM eclipse-temurin:21-jre-alpine
RUN apk add --no-cache libpcap
COPY target/Analizer-1.0-SNAPSHOT.jar /app/analyzer.jar
WORKDIR /app
ENTRYPOINT ["java", "-jar", "analyzer.jar"]