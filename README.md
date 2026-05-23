# OpenSSL Hybrid Encryption Test

Test C++17 project for hybrid file encryption with OpenSSL:

- RSA key pair generation
- AES file encryption
- RSA encryption of the temporary AES key
- streaming file encryption/decryption

The application creates a small test file, encrypts it, decrypts it back, and writes the restored result.

## Requirements

- CMake 3.24 or newer
- C++17 compiler
- On Windows: Visual Studio Build Tools or Visual Studio with the Desktop development with C++ workload

On Windows, `CMakeLists.txt` downloads a pre-built OpenSSL package with `FetchContent` and copies the required DLLs next to the executable.

## Build

From the project directory:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

If you changed CMake options or headers and want a clean rebuild:

```powershell
cmake --build build --config Release --clean-first
```

## Run

With Visual Studio generators, the executable is usually in `build\Release`:

```powershell
cd build\Release
.\crypto_app.exe
```

The program generates these files in the current working directory:

- `private.pem`
- `public.pem`
- `important_data.txt`
- `important_data.enc`
- `restored_data.txt`

Expected console output:

```text
Generating RSA-4096 key pair...
Success! Saved 'private.pem' and 'public.pem'.
Encrypting file with public key...
Decrypting file with private key...
Done! Verify 'restored_data.txt' matching original inputs.
```

No output means the files match.

## Notes

If CMake reports `No CMAKE_CXX_COMPILER could be found`, install Visual Studio Build Tools and enable the C++ desktop workload.

If the executable cannot find OpenSSL DLLs, rebuild the project so the post-build copy step can place the DLLs next to `crypto_app.exe`.
