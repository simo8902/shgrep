
    
  
@echo off
setlocal EnableExtensions DisableDelayedExpansion
set "DRY=0"
if /i "%~1"=="--dry-run" set "DRY=1"
if /i "%~1"=="--help" (
  echo Usage: %~nx0 [--dry-run]
  exit /b 0
)

if "%DRY%"=="1" (echo [PREVIEW] No files will be deleted.) else (echo [CLEAN] Cache cleanup started.)
echo Close browsers, Spotify, IDEs and build tools first for best results.
echo.

rem Python / Conda / uv / Node / Rust / Java cache managers.
call :Run pip cache purge
call :Run pip3 cache purge
call :Run uv cache clean
call :Run conda clean --all --yes
call :Run npm cache clean --force
call :Run pnpm store prune
call :Run yarn cache clean
call :Run dotnet nuget locals all --clear
call :Run docker builder prune --all --force

rem Python, uvx, Conda, Node, Rust and build-system download caches.
call :Empty "%LOCALAPPDATA%\pip\Cache"
call :Empty "%LOCALAPPDATA%\uv\cache"
call :Empty "%APPDATA%\uv\cache"
call :Empty "%USERPROFILE%\.cache\uv"
call :Empty "%USERPROFILE%\.cache\pip"
call :Empty "%USERPROFILE%\.cache\pre-commit"
call :Empty "%USERPROFILE%\.cache\ruff"
call :Empty "%USERPROFILE%\.npm\_cacache"
call :Empty "%LOCALAPPDATA%\npm-cache\_cacache"
call :Empty "%LOCALAPPDATA%\Yarn\Cache"
call :Empty "%LOCALAPPDATA%\pnpm-cache"
call :Empty "%USERPROFILE%\.cargo\registry\cache"
call :Empty "%USERPROFILE%\.cargo\git\db"
call :Empty "%USERPROFILE%\.gradle\caches\build-cache-1"
call :Empty "%USERPROFILE%\.gradle\caches\build-cache-2"
call :Empty "%USERPROFILE%\.m2\repository\.cache"
call :Empty "%USERPROFILE%\.cache\ccache"
call :Empty "%LOCALAPPDATA%\ccache"
call :Empty "%LOCALAPPDATA%\sccache"
call :Empty "%USERPROFILE%\.cache\sccache"
call :Empty "%LOCALAPPDATA%\clangd\index"
call :Empty "%USERPROFILE%\.cache\clangd"
call :Empty "%LOCALAPPDATA%\clang\ModuleCache"
call :Empty "%LOCALAPPDATA%\Temp\clangd"
call :Empty "%LOCALAPPDATA%\Temp\llvm"

rem GPU driver shader caches, not driver installation files.
call :Empty "%LOCALAPPDATA%\AMD\DxCache"
call :Empty "%LOCALAPPDATA%\AMD\GLCache"
call :Empty "%LOCALAPPDATA%\AMD\VkCache"
call :Empty "%LOCALAPPDATA%\D3DSCache"
call :Empty "%LOCALAPPDATA%\NVIDIA\DXCache"
call :Empty "%LOCALAPPDATA%\NVIDIA\GLCache"
call :Empty "%PROGRAMDATA%\NVIDIA Corporation\NV_Cache"

rem Browser caches, preserving cookies, history, logins and profiles.
for /d %%P in ("%LOCALAPPDATA%\Google\Chrome\User Data\*") do (
  call :Empty "%%~fP\Cache"
  call :Empty "%%~fP\Code Cache"
  call :Empty "%%~fP\GPUCache"
  call :Empty "%%~fP\Network\Cache"
  call :Empty "%%~fP\Service Worker\CacheStorage"
)
for /d %%P in ("%LOCALAPPDATA%\Microsoft\Edge\User Data\*") do (
  call :Empty "%%~fP\Cache"
  call :Empty "%%~fP\Code Cache"
  call :Empty "%%~fP\GPUCache"
  call :Empty "%%~fP\Network\Cache"
)
for /d %%P in ("%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*") do (
  call :Empty "%%~fP\cache2"
  call :Empty "%%~fP\startupCache"
)
rem Spotify desktop installer: preserve offline downloads in Spotify\Storage/Data.
call :Empty "%APPDATA%\Spotify\Browser\Cache"
call :Empty "%APPDATA%\Spotify\Browser\Code Cache"
call :Empty "%APPDATA%\Spotify\Browser\GPUCache"
call :Empty "%APPDATA%\Spotify\GPUCache"
call :Empty "%LOCALAPPDATA%\Spotify\Browser\Cache"
call :Empty "%LOCALAPPDATA%\Spotify\Browser\Code Cache"
call :Empty "%LOCALAPPDATA%\Spotify\GPUCache"

rem Windows temporary files and disposable application/web caches.
call :Empty "%TEMP%"
call :Empty "%LOCALAPPDATA%\Temp"
call :Empty "%WINDIR%\Temp"
call :Empty "%LOCALAPPDATA%\Microsoft\Windows\INetCache"
for /d %%P in ("%LOCALAPPDATA%\Packages\*") do (
  call :Empty "%%~fP\AC\INetCache"
  call :Empty "%%~fP\AC\INetCookies\Low\Cache"
  call :Empty "%%~fP\LocalCache\Cache"
  call :Empty "%%~fP\LocalCache\GPUCache"
  call :Empty "%%~fP\LocalCache\Code Cache"
  call :Empty "%%~fP\LocalCache\Microsoft\Windows\INetCache"
)

rem Remove only thumbnail cache files, not the Explorer directory.
for %%F in ("%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db") do call :File "%%~fF"

echo.
echo Finished. Locked files and unavailable tools are skipped.
exit /b 0

:Run
where "%~1" >nul 2>&1 || exit /b 0
if "%DRY%"=="1" (
  echo [PREVIEW CMD] %*
) else (
  echo [CMD] %*
  %*
)
exit /b 0

:Empty
if "%~1"=="" exit /b 0
if not exist "%~1\" exit /b 0
if "%DRY%"=="1" (
  echo [PREVIEW DIR] %~1
  exit /b 0
)
echo [CLEAR] %~1
for /d %%D in ("%~1\*") do rd /s /q "%%~fD" >nul 2>&1
del /f /q /a "%~1\*" >nul 2>&1

