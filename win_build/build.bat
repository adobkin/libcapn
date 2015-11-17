@echo off

set VC_PATH="%PROGRAMFILES%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
if exist %PROGRAMFILES(X86)% (
	set VC_PATH="%PROGRAMFILES(X86)%\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"
) 

if not exist %VC_PATH% (
	echo "Microsoft Visual Studio 14.0 not found"
	goto :eof
)

call "C:\Program Files\Microsoft Visual Studio 14.0\VC\vcvarsall.bat"

@echo.
@echo =================================
@echo Build Shared Library
@echo =================================
@echo.

cmake . -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
nmake
nmake install

@echo. 
@echo =================================
@echo Build Static Library
@echo =================================
@echo. 

nmake clean
cmake . -G "NMake Makefiles" -DBUILD_SHARED_LIBS=NO -DCMAKE_BUILD_TYPE=Release
nmake
nmake install

nmake zip
