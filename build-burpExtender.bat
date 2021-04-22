@echo off
rem set your jdk dictionary
set path=%path%;C:\Java\jdk1.8.0_151\bin
set classpath=./src
for /f "delims=" %%i in ('cd') do set dictionary=%%i
if exist %dictionary%\classes (
    echo.
) else (
    mkdir classes
)
javac -encoding UTF8 -d classes/ src/jsoncomp/*.java
javac -encoding UTF8 -d classes/ src/burp/BurpExtender.java
xcopy %dictionary%\src\burp\autologin\resources\default_config.json %dictionary%\classes\burp\autologin\resources\default_config.json /Y /I /E /F
cd classes && jar cvf ../autoLogin.jar burp jsoncomp