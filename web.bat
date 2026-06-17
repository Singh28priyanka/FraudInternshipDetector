@echo off
REM Compile and launch the WEB version (opens at http://localhost:8090).
REM Optional: pass a port, e.g.  web.bat 9000
cd /d "%~dp0"
echo Compiling...
javac *.java
if errorlevel 1 goto :eof
echo Starting web server...
java WebServer %*
