#
# Build stage
#
FROM maven:3.8.3-jdk-8-slim AS build
COPY ./login-service /home/app/login-service
RUN mvn -f /home/app/login-service/pom.xml clean package

#
# Package stage
#
FROM java:8-jdk
EXPOSE 8080
COPY --from=build /home/app/login-service/target/login-0.1.0.jar /
CMD ["java","-jar","login-0.1.0.jar"]