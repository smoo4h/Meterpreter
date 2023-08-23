@ECHO OFF

del *.dll

msbuild .\sRDI-MkDir.sln /p:configuration=Release;Platform=x64
IF %ERRORLEVEL% NEQ 0 ( 
   goto :Fail
)
copy /Y .\x64\Release\sRDI-MkDir.dll mkdir_x64.dll

msbuild .\sRDI-MkDir.sln /p:configuration=Release;Platform=x86
IF %ERRORLEVEL% NEQ 0 ( 
   goto :Fail
)
copy /Y .\Release\sRDI-MkDir.dll mkdir_x86.dll

exit /b 0

:Fail
echo Failed to compile
exit /b 9993