@ECHO OFF

msbuild .\sRDI-BypassUAC.sln /p:configuration=Release

copy /y x64\Release\sRDI-BypassUAC.dll ..\Loader\bin\