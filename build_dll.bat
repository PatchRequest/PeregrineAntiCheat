@echo off
setlocal

set MSBUILD="C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set DLL_SLN=src\PeregrineDLL\PeregrineDLL.sln
set DRV_SLN=src\PeregrineKernelComponent\PeregrineKernelComponent.sln
set DEST=src\Userland

echo === Building PeregrineDLL Release x64 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x64 /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: DLL x64 build failed
    exit /b 1
)

echo === Building PeregrineDLL Release x86 ===
%MSBUILD% %DLL_SLN% /p:Configuration=Release /p:Platform=x86 /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: DLL x86 build failed
    exit /b 1
)

echo === Building PeregrineKernelComponent Release x64 ===
%MSBUILD% %DRV_SLN% /p:Configuration=Release /p:Platform=x64 /m /v:minimal
if %ERRORLEVEL% neq 0 (
    echo ERROR: Driver build failed
    exit /b 1
)

echo === Copying files to %DEST% ===
copy /Y "src\PeregrineDLL\x64\Release\PeregrineDLL.dll" "%DEST%\PeregrineDLL_x64.dll"
copy /Y "src\PeregrineDLL\Release\PeregrineDLL.dll" "%DEST%\PeregrineDLL_x86.dll"
copy /Y "src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" "%DEST%\PeregrineKernelComponent.sys"

echo === Copying to C:\Peregrine ===
if not exist "C:\Peregrine" mkdir "C:\Peregrine"
copy /Y "src\PeregrineDLL\x64\Release\PeregrineDLL.dll" "C:\Peregrine\Peregrine64.dll"
copy /Y "src\PeregrineDLL\Release\PeregrineDLL.dll" "C:\Peregrine\Peregrine32.dll"
copy /Y "src\PeregrineKernelComponent\x64\Release\PeregrineKernelComponent.sys" "C:\Peregrine\PeregrineKernelComponent.sys"
if exist "src\peregrine-tauri\src-tauri\target\release\peregrine-tauri.exe" (
    copy /Y "src\peregrine-tauri\src-tauri\target\release\peregrine-tauri.exe" "C:\Peregrine\peregrine-tauri.exe"
)

echo === Done ===
dir "C:\Peregrine\"
