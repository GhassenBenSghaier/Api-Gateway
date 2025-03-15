# Use an official OpenJDK runtime as the base image
FROM openjdk:17-jdk-slim

# Install curl and dnsutils for troubleshooting
RUN apt-get update && apt-get install -y curl dnsutils

# Set the working directory inside the container
WORKDIR /app

# Copy the Spring Boot JAR file into the container
COPY target/api-gateway-0.0.1-SNAPSHOT.jar app.jar

# Expose the port defined in application.yml (9999)
EXPOSE 9999

# Run the JAR file
ENTRYPOINT ["java", "-jar", "app.jar"]