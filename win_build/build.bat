@echo off

set VC_PATH="%PROGRAMFILES%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
if exist %PROGRAMFILES(X86)% (
	set VC_PATH="%PROGRAMFILES(X86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
) 

if not exist %VC_PATH% (
	echo "Microsoft Visual Studio 14.0 not found"
	goto :eof
)

echo call "C:\Program Files\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
call "C:\Program Files\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
cmake . -G "NMake Makefiles"
nmake
nmake install
nmake zip
