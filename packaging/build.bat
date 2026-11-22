@echo off
REM Build ngm-panel.exe on Windows (cmd.exe)
setlocal
cd /d "%~dp0.."

echo == ngm-panel build ==
python --version || goto :error

echo.
echo -- offline tests --
python -m unittest discover -s tests || goto :error
python -m ngm_panel catalog --check || goto :error

echo.
echo -- installing PyInstaller --
python -m pip install --upgrade pyinstaller || goto :error

echo.
echo -- building exe --
python -m PyInstaller packaging\ngm-panel.spec --noconfirm --clean || goto :error
if not exist "dist\ngm-panel.exe" goto :error

echo.
echo -- smoke test --
".\dist\ngm-panel.exe" --version || goto :error
".\dist\ngm-panel.exe" catalog --check || goto :error

echo.
echo Done. Run:  dist\ngm-panel.exe run
exit /b 0

:error
echo.
echo BUILD FAILED (exit %errorlevel%)
exit /b 1
