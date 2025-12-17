@echo off
echo ========================================================
echo   SecureCodeX GitHub Uploader
echo ========================================================
echo.

set GIT_PATH="C:\Program Files\Git\cmd\git.exe"

if not exist %GIT_PATH% (
    echo [ERROR] Git executable not found at %GIT_PATH%
    echo Please verify your Git installation.
    pause
    exit /b 1
)

echo [INFO] Git found at %GIT_PATH%

echo [INFO] Pushing to GitHub (https://github.com/nishanthan008/SecureCodeX.git)...
echo.
echo [NOTE] You may be asked to sign in to GitHub in the popup window.
echo.

%GIT_PATH% push -u origin main

echo.
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] Code successfully uploaded to GitHub!
) else (
    echo [ERROR] Push failed. Please check your internet connection or GitHub credentials.
)
pause
