@echo off
REM Compile and launch the Fraud Internship Detector (Windows).
cd /d "%~dp0"
echo Compiling...
javac *.java
if errorlevel 1 goto :eof
echo Starting app...
java Main
