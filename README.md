# PoC PE-Runtime-Crypter
A runtime Crypter written in C++ for native x64 PE files to bypass AVs signature based detection.

## How to build
- build stub.cpp
- insert raw Data of the stub in crypter.cpp (I used HxD to export a C/C++ bytearray)
- build crypter.cpp

## How to use

Either via command line argument
```cmd
C:\path\to\crypter.exe C:\path\to\target.exe
```

Or simply via drag & drop

![test](https://user-images.githubusercontent.com/79810730/210828228-24d4813f-6294-4832-afe0-1f2feb301bae.gif)

For more information and improvement tips visit my github [pages](https://ricky5panish.github.io/pe-runtime-crypter.html)
