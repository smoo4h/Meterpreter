@ECHO OFF

msbuild GDI-ScreenShot/GDI-ScreenShot.sln /p:Platform=x64 /p:Configuration=Release
copy /y GDI-ScreenShot\x64\Release\GDI-ScreenShot.exe