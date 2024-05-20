 # iris-pkcs7-utils

This is a set of utilities for working with PKCS#7 files. It is based on the python libraries `asn1crypto` and `pyopenssl`.

This utility is intended to be used with IRIS and IRIS for Heath from an COS environment.

It's distributed on ZPM/IPM.

## Installation

```objectscript
zpm "install pkcs7-utils"
```

with pip :

```bash
pip install https://github.com/grongierisc/iris-pkcs7-util/releases/download/v0.0.1/iris_gen_cms-0.0.1-py3-none-any.whl
```

## Usage

```objectscript
	set tUtils = ##class(dc.cms.Encrypt).%New()
	set tCertFileName = "/path/to/cert/file.crt.pem"
	set tKeyFileName = "/path/to/key/file.key.pem"
	set tPassPhrase = "***********"
	set tContent = ##class(%Stream.FileCharacter).%New()
	$$$ThrowOnError(tContent.LinkToFile("/path/to/content/to/be/signed.txt"))
	set tStream = ##class(%Stream.FileBinary).%New()
	do tStream.LinkToFile("/path/to/output/file/for/cms/binary.cms")
	$$$ThrowOnError(tUtils.CreateCMSStream(tContent,tCertFileName, tKeyFileName, tPassPhrase, .tStream))
	set tsc = tStream.%Save()
```

## Command line

```bash
gencms -h
```

result:

```bash
usage: gencms [-h] content_filename cert_filename key_filename key_password output_filename

Generate a CMS file

positional arguments:
  content_filename  the file to sign
  cert_filename     the certificate to use
  key_filename      the private key to use
  key_password      the private key password
  output_filename   the output CMS file

optional arguments:
  -h, --help        show this help message and exit
```

example:

```bash
gencms misc\in\test.txt misc\cert\asip-p12-EL-TEST-ORG-SIGN-20240304-094358.crt.pem misc\cert\asip-p12-EL-TEST-ORG-SIGN-20240304-094358.key.pem Intersystems2024! misc/out/toto.cms
```