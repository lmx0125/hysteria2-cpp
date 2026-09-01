@echo off
REM build.bat - Build hy2-cpp tests
REM Usage: build

echo Building hy2-cpp tests...

if not exist "build" (
    cmake -S . -B build -G "Visual Studio 17 2022" -DHY2_WITH_QUIC_BACKEND=OFF
)

cmake --build build --target hy2_tests --config Release

echo Done!
.\build\tests\Release\hy2_tests.exe
