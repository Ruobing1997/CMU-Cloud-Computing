#
# Build stage
#
FROM maven:3.8.3-jdk-8-slim AS build
COPY ./group-chat-service /home/app/group-chat-service
RUN mvn -f /home/app/group-chat-service/pom.xml clean package

#
# Package stage
#
FROM java:8-jdk
EXPOSE 8080
COPY --from=build /home/app/group-chat-service/target/groupchat-0.1.0.jar /
CMD ["java","-jar","groupchat-0.1.0.jar"]