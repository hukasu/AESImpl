# AES
An implementation of the AES standard

## Disclaimer
This implementation only includes ECB mode, which is unsafe.

## Dependencies
This project uses no external dependencies.  
This project uses C++17 standard.

## Building
Building with Cmake consists of configuring the project, and then building it.
```bash
mkdir build/
cd build
cmake ..
cmake --build .
```

### Command line tool
This project contains a simple command line tool. To build it configure the project with `BUILD_COMMAND_LINE_TOOL`, then build.
```bash
cmake -BUILD_COMMAND_LINE_TOOL:BOOL=TRUE ..
cmake --build .
```
Now you can use the command line tool to encrypt a file.
```bash
aes <path_to_file> <path_to_encrypted_output> <encryption_key>
```
**Note:** The command line tool is not safe due to the key being passed as a string.

## Tests
The project contains a few test vectors. To run the test vectors first configure the project with `BUILD_TESTS`, then build.
```bash
cmake -DBUILD_TESTS:BOOL=TRUE ..
cmake --build .
```
Then run the command.
```bash
ctest -C Debug
```

## Reference
https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf