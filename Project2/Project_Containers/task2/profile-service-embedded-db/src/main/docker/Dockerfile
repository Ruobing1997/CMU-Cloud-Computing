#
# Build stage
#
FROM maven:3.8.3-jdk-8-slim AS build
COPY ./profile-service-embedded-db /home/app/profile-service-embedded-db
RUN mvn -f /home/app/profile-service-embedded-db/pom.xml clean package

#
# Package stage
#
FROM java:8-jdk
EXPOSE 8080
COPY --from=build /home/app/profile-service-embedded-db/target/profile-embedded-0.1.0.jar /
CMD ["java","-jar","profile-embedded-0.1.0.jar"]