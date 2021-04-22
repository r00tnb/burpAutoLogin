@echo off
rem set your jdk dictionary
set path=%path%;C:\Java\jdk1.8.0_151\bin
set classpath=./src
set outdir=Tests
for /f "delims=" %%i in ('cd') do set dictionary=%%i
if exist %dictionary%\%outdir% (
    echo.
) else (
    mkdir %outdir%
)
javac -encoding UTF8 -d %outdir%/ src/jsoncomp/json/*.java
javac -encoding UTF8 -d %outdir%/ src/jsoncomp/*.java
javac -encoding UTF8 -d %outdir%/ src/*.java
set classpath=
cd %outdir% && java Test && exit