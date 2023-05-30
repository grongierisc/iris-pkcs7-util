 # iris-pkcs7-utils

This is a set of utilities for working with PKCS#7 files. It is based on the python libraries `asn1crypto` and `pyopenssl`.

This utility is intended to be used with IRIS and IRIS for Heath from an COS environment.

It's distributed on ZPM/IPM.

## Installation

```objectscript
zpm "install pkcs7-utils"
```

## Usage

```objectscript
    set tUtils = ##class(dc.cms.Utils).%New()
    set tCertFileName = "cert.pem"
    set tKeyFileName = "key.pem"
    set tPassPhrase = "TOTO"
    set tContent = ##class(%Stream.FileCharacter).%New()
    $$$ThrowOnError(tContent.LinkToFile("content.txt"))


    $$$ThrowOnError(tUtils.CreateCMSStream(tContent,tCertFileName, tKeyFileName, tPassPhrase, .tStream))
    zwrite tStream
```