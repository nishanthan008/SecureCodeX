@echo off
echo ========================================================
echo   SecureCodeX GitHub Uploader
echo ========================================================
echo.

:: Check if git is available
where git >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Git is not installed or not in your PATH.
    echo.
    echo Please install Git for Windows first:
    echo https://git-scm.com/download/win
    echo.
    echo After installing, restart this script.
    pause
    exit /b 1
)

echo [INFO] Git found. initializing repository...
git init

echo [INFO] Adding files...
git add .

echo [INFO] Committing files...
git commit -m "Initial release of SecureCodeX CLI tool"

echo [INFO] Renaming branch to main...
git branch -M main

echo [INFO] Adding remote origin...
git remote remove origin 2>nul
git remote add origin https://github.com/nishanthan008/SecureCodeX.git

echo [INFO] Pushing to GitHub...
echo.
git push -u origin main

echo.
if %ERRORLEVEL% equ 0 (
    echo [SUCCESS] Code successfully uploaded to GitHub!
) else (
    echo [ERROR] Push failed. Please check your internet connection or GitHub credentials.
)
pause
