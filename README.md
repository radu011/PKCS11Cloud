# PKCS11Cloud

## Introduction

! ! ! Project description

Plugin written in PKCS#11 that uses the CSC standard to make remote signatures, without using a physical cryptographic token.

## Structure

- /bin : binaries needed for SoftHSMv2 build
- /docs :
- /include : include directory for CSCClient
- /lib : lib directory for CSCClient
- /Logs : some old logs for specific error cases
- /p8key : certificate and keys added to the token (will not be used by the user)
- /plugins : dlls used for testing | dll logger | PKCS11Cloud dll version 1
- /SoftHSMv2-x64 : modified SoftHSMv2 project to use CSC
- /tools : other software used
- /wxWidgets : the files used for the wxWidgets GUI project inside SoftHSMv2-x64 project

## Dependencies

PKCS11Cloud depends on multiple libraries/projects:

- SoftHSMv2
  - OpenSSL
  - CppUnit
- cURL
- cJson
- wxWidgets

## Use dll without project build

You will find all you need in /plugins/SoftHSMv2-dll-v1

1. Copy files on local computer

2. In 'softhsm2.conf' file, on third line modify 'path to token folder' with absolute path to /tokens directory from same folder

3. Set the environment variable SOFTHSM2_CONF with the value indicating the path to the file 'softhsm2.conf'

## Installation

### Configure

After downloading this repository, you must do the following steps.

All these steps are used directly on ther project from this repository.

NOTE: Put openssl and cppunit on /bin folder

1. Use [SoftHSMv2 github](https://github.com/opendnssec/SoftHSMv2/) for platform specific installing notes

   - [WIN32-NOTES.md](https://github.com/opendnssec/SoftHSMv2/blob/develop/WIN32-NOTES.md) for Windows
   - [README.md](https://github.com/opendnssec/SoftHSMv2/blob/develop/README.md) for Linux
   - [OSX-NOTES.md](https://github.com/opendnssec/SoftHSMv2/blob/develop/OSX-NOTES.md) for Mac OS

2. Build wxWidgets from their repository ( [link](https://github.com/wxWidgets/wxWidgets) ) and put /include and /lib in the /wxWidgets directory from this project (you can skip this step is there is no problem on project build, just go to the /wxWidgets directory and extract lib.zip archive)

### Initialize Tokens

Use either softhsm2-util or the PKCS#11 interface. The SO PIN can e.g. be used
to re-initialize the token and the user PIN is handed out to the application so
it can interact with the token.

      softhsm2-util --init-token --slot 0 --label "My token 1"

Type in SO PIN and user PIN. Once a token has been initialized, more slots will
be added automatically with a new uninitialized token.

Initialized tokens will be reassigned to another slot (based on the token
serial number). It is recommended to find and interact with the token by
searching for the token label or serial number in the slot list / token info.

Another util commands:

<pre>
# list slots
softhsm2-util --show-slots
# delete token
softhsm2-util --delete-token --token "mytoken" 
# initialize token
softhsm2-util --init-token --slot < slot number > --label "mytoken"
# import key
softhsm2-util --import < private key path > --slot < slot id > --label < label > --id < slot id > --pin < pin >
# example
softhsm2-util --import C:\Users\...\path\...\private_key.pem --slot 1270533568 --label "RO" --id 6c23cae1826417517b65f4a19595069159b171d7 --pin 12345
</pre>

NOTE: 'id' from import command must be equal with Thumbprint value from certificate

## Backup

All of the tokens and their objects are stored in the location given by
softhsm2.conf. Backup can thus be done as a regular file copy.

## Log information

Log information is sent to syslog or the Windows event log and the log
level is set in the configuration file. Each log event is prepended with
the source file name and line number.
