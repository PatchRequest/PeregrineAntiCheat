@echo off
where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

echo === Building test tools ===
cl /nologo /O2 game.c /Fe:game.exe
cl /nologo /O2 cheat.c /Fe:cheat.exe
cl /nologo /O2 cheat_inject.c /Fe:cheat_inject.exe
cl /nologo /O2 cheat_shellcode.c /Fe:cheat_shellcode.exe
cl /nologo /O2 cheat_patch.c /Fe:cheat_patch.exe /link psapi.lib
cl /nologo /O2 CheatEngine.c /Fe:CheatEngine.exe
cl /nologo /O2 /LD payload.c /Fe:payload.dll

echo.
echo === Built ===
dir /b *.exe *.dll 2>nul
echo.
echo === Usage ===
echo.
echo 1. RPM/WPM cheat (DLL hooks + ETW-TI + ObCallback):
echo    game.exe                        ^<-- note PID + address
echo    cheat.exe ^<PID^> ^<address^>
echo.
echo 2. DLL injection (CreateRemoteThread + ObCallback + ETW-TI):
echo    game.exe                        ^<-- note PID
echo    cheat_inject.exe ^<PID^> payload.dll
echo.
echo 3. Shellcode injection (VirtualAllocEx + RemoteThread + Thread RIP scan):
echo    game.exe                        ^<-- note PID
echo    cheat_shellcode.exe ^<PID^>
echo.
echo 4. Code patching (Module Integrity / tamper detection):
echo    game.exe                        ^<-- note PID
echo    cheat_patch.exe ^<PID^>          ^<-- then click Check Modules
echo.
echo 5. Blacklist detection:
echo    CheatEngine.exe                 ^<-- then click Blacklist in Peregrine
