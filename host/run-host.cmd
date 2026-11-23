@echo off
setlocal
for %%P in (
  "%ProgramFiles%\nodejs\node.exe"
  "%LOCALAPPDATA%\Programs\nodejs\node.exe"
  "%NVM_SYMLINK%\node.exe"
  "%USERPROFILE%\.volta\bin\node.exe"
  "%SCOOP%\apps\nodejs\current\node.exe"
  "%USERPROFILE%\scoop\apps\nodejs\current\node.exe"
) do (
  if exist "%%~P" (
    "%%~P" "%~dp0host.mjs" %*
    exit /b
  )
)
node "%~dp0host.mjs" %*
