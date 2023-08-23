@ECHO OFF
if NOT EXIST bin mkdir bin
 
msbuild ShellcodeRDI.sln /p:Configuration=Release /p:Platform=x64
copy /y x64\Release\Native.exe NativeLoader_x64.exe
copy /y NativeLoader_x64.exe bin\

msbuild ShellcodeRDI.sln /p:Configuration=Release /p:Platform=Win32
copy /y Release\Native.exe NativeLoader_x86.exe
copy /y NativeLoader_x86.exe bin\
