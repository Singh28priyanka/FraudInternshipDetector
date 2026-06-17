# Build & run the web version anywhere that supports Docker
# (Render, Railway, Fly.io, a VPS, etc.). The host injects $PORT; WebServer reads it.
FROM eclipse-temurin:21-jdk
WORKDIR /app
COPY *.java ./
RUN javac *.java
EXPOSE 8090
CMD ["java", "WebServer"]
