@ECHO OFF

msbuild Client.sln /p:Platform=x64 /p:Configuration=Release
copy /y x64\Release\Client.exe