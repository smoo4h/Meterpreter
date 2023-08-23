@ECHO OFF

msbuild .\Getsystem-via-Pipe\Getsystem-via-Pipe.sln /p:configuration=Release
copy /Y .\Getsystem-via-Pipe\x64\Release\Getsystem-via-Pipe.exe
