English | [简体中文](./README.CN.md) 

# Bin_info: Cross-Platform Binary Parsing Tool
Bin_info is a cross-platform binary parsing command-line tool implemented in Rust. It supports parsing file information for PE, ELF, and Mach-O formats. Bin_info can be used as a standalone tool for binary file analysis or integrated into other projects as a library to directly parse binary files.

# Key Parsing Features
* 1.Basic Binary Information
> File size
> Hash values (MD5, SHA-1, SHA-256)
> SSDeep hash
> File type

* 2.Execution Information
> Entry point address
> Instruction set architecture

* 3.Section Information
> Names, offsets, sizes, and attributes of each section

* 4.Import Table
> List of imported libraries and functions

* 5.Export Table
> List of exported functions and symbols

* 6.Certificate Information
> Details of embedded digital signatures and certificates

* 7.Embedded Strings
> Extraction of strings from the file

# Platform Support
Bin_info supports the following operating systems:
* Windows
* macOS
* Linux
* And any other platform that supports Rust compilation

# Use Cases
* **Security Analysis**: Assists in analyzing the security of executable files and detecting potential malicious code.
* **Reverse Engineering**: Aids reverse engineers in understanding the structure of binary files.
* **Automation Tools**: Can be integrated into CI/CD pipelines to automatically parse and verify binary files.

example:
```
# bin_info /tmp/test.dll
  ____    _             ___            __         
 | __ )  (_)  _ __     |_ _|  _ __    / _|   ___  
 |  _ \  | | | '_ \     | |  | '_ \  | |_   / _ \ 
 | |_) | | | | | | |    | |  | | | | |  _| | (_) |
 |____/  |_| |_| |_|   |___| |_| |_| |_|    \___/ 
                                                  

✔ analysis complete
Base Info:
+-----------+-----------------------------------------------------------------------+
| base info | value                                                                 |
+===================================================================================+
| path      | /tmp/test.dll                                                         |
|-----------+-----------------------------------------------------------------------|
| size      | 6.3 MB (6279632)                                                      |
|-----------+-----------------------------------------------------------------------|
| md5       | e82d1a409fb1b4239bde28facc98e11d                                      |
|-----------+-----------------------------------------------------------------------|
| sha1      | 782aadef7eb64f1ee58a75d28fd6af6eb7d331ea                              |
|-----------+-----------------------------------------------------------------------|
| sha256    | 7bf4666a6a89e723cf6eb309abe7da8b33edb4198fe12934e4b1ddf95e9aa113      |
|-----------+-----------------------------------------------------------------------|
| ssdeep    | 98304:DfuQgYrn+1tQ7V27D/7Hfxco++Js8iNOjdiubYw/2pJ:DfuQgYrn+1tQcD/O8qt |
|-----------+-----------------------------------------------------------------------|
| file_type | exe                                                                   |
+-----------+-----------------------------------------------------------------------+

Execute Info:
+--------------+----------+
| execute info | value    |
+=========================+
| entry        | 0x28276c |
|--------------+----------|
| architecture | X86      |
+--------------+----------+

others...
```