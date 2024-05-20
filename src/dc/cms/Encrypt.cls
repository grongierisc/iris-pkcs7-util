/// Small class that make use of 2 python library (asn1crypto and OpenSSL) to create a CMS file
/// Usage : create a new instance of the class and use <METHOD>CreateCMSStream</METHOD> it will output in the last parametter a stream with a binary CMS file in it.
Class dc.cms.Encrypt Extends %RegisteredObject
{

XData %import [ MimeType = application/python ]
{
import iris
from asn1crypto import cms,x509,pem
from OpenSSL import crypto
from datetime import datetime,timezone
}

/// Set a stream with a binary CMS file content
/// <PARAMETER>pContent</PARAMETER> : The content you want to sign
/// <PARAMETER>pCertFileName</PARAMETER> : The path to the Certificate file (.crt.pem)
/// <PARAMETER>pKeyFileName</PARAMETER> : The path to the key file (.key.pem)
/// <PARAMETER>pPassword</PARAMETER> : The password or passphrase of the certificate
/// <PARAMETER>pResult</PARAMETER> : A stream in wich the cms file binary will be filled, must be instanciated beforehand (set the output / linktofile before the use of this method)
/// <EXAMPLE>
/// set tUtils = ##class(dc.cms.Encrypt).%New()
/// 	set tCertFileName = "/path/to/cert/file.crt.pem"
/// 	set tKeyFileName = "/path/to/key/file.key.pem"
/// 	set tPassPhrase = "***********"
/// 	set tContent = ##class(%Stream.FileCharacter).%New()
/// 	$$$ThrowOnError(tContent.LinkToFile("/path/to/content/to/be/signed.txt"))
/// 	set tStream = ##class(%Stream.FileBinary).%New()
/// 	do tStream.LinkToFile("/path/to/output/file/for/cms/binary.cms")
/// 	$$$ThrowOnError(tUtils.CreateCMSStream(tContent,tCertFileName, tKeyFileName, tPassPhrase, .tStream))
/// 	set tsc = tStream.%Save()
///  </EXAMPLE>
Method CreateCMSStream(pContent As %Stream.FileCharacter, pCertFileName As %String, pKeyFileName As %String, pPassword As %String, Output pResult As %Stream.TmpCharacter) As %Status
{
	Set tSC = $$$OK
	// Convert the content to bytes
	Set tContentBytes = ..ConvertStreamToString(pContent)
	set tResultBytes = ..GenerateCMS(tContentBytes,pCertFileName,pKeyFileName,pPassword)
	// Convert the result to a stream
	do ..ConvertStringToStream(tResultBytes, .pResult)
	Quit tSC
}

// ToDo test with big files 3,6 + MB

Method ConvertStreamToString(pStream As %Stream.FileBinary) As %String
{
	set builtins = ##class(%SYS.Python).Import("builtins")
	set tString = ""
	while 'pStream.AtEnd{
		set tString = tString_pStream.Read($$$MaxStringLength)
	}
	return tString
}

// Todo faire une boucle (hint : chunk)

Method ConvertStringToStream(pString, Output pStream As %Stream.FileBinary)
{
	do pStream.Write(pString)
	do pStream.Rewind()
}

Method loadCertificates(pCertfilename) As %String
{
	set fileStream = ##class(%Stream.FileBinary).%New()
	set tSC = fileStream.LinkToFile(pCertfilename)
	set derBytes = ##class(%SYS.Python).Bytes(fileStream.Read())
	set pem = ##class(%SYS.Python).Import("asn1crypto.pem")
	set x509 = ##class(%SYS.Python).Import("asn1crypto.x509")
	if pem.detect(derBytes){
		set derBytes = ##class(%SYS.Python).Bytes(pem.unarmor(derBytes)."__getitem__"(2))
	}
	set cert = x509.Certificate.load(derBytes)
	return cert
}

Method loadPrivateKey(pKeyfilename, pKeypassword) As %String
{
	// load the private key
	set fileStream = ##class(%Stream.FileBinary).%New()
	set tSC = fileStream.LinkToFile(pKeyfilename)
	set keyFileBytes = ##class(%SYS.Python).Bytes(fileStream.Read())
	set crypto = ##class(%SYS.Python).Import("OpenSSL.crypto")
	set keyBytes =  ##class(%SYS.Python).Bytes($ZCVT(pKeypassword, "I", "UTF8"))
	set key = crypto."load_privatekey"(crypto."FILETYPE_PEM", keyFileBytes,keyBytes)
	return key
}

Method certificateDateCheck(pCert)
{
	set pyDateTime = ##class(%SYS.Python).Import("datetime")
	set now = pyDateTime.datetime.now(pyDateTime.timezone.utc)
	// validate the certificate
	if pCert."not_valid_before"."__gt__"(now){
		THROW ##class(%Exception.General).%New("certificate date exception","5001",,"Certificate not valid yet")
	}
	if pCert."not_valid_after"."__lt__"(now){
		THROW ##class(%Exception.General).%New("certificate date exception","5001",,"Certificate expired")
	}
}

Method certificateUsageCheck(pCert) As %String
{
	if (pCert."key_usage_value" && 'pCert."key_usage_value".native."__contains__"("digital_signature")){
		THROW ##class(%Exception.General).%New("not allowed exception","5001",,"Certificate not allowed for digital signature")
	}
}

Method GenerateCMS(pContent, pCertfilename, pKeyfilename, pkeypassword) As %String
{
	set json = ##class(%SYS.Python).Import("json")
	set builtins = ##class(%SYS.Python).Import("builtins")
	set crypto = ##class(%SYS.Python).Import("OpenSSL.crypto")
	set cms = ##class(%SYS.Python).Import("asn1crypto.cms")
	set x509 = ##class(%SYS.Python).Import("asn1crypto.x509")

	// load the certificate
	set cert = ..loadCertificates(pCertfilename)

	// validate the certificate
	do ..certificateDateCheck(cert)
	do ..certificateUsageCheck(cert)

	// load the private key
	set key = ..loadPrivateKey(pKeyfilename, pkeypassword)

	// sign the content
	set signature =  ##class(%SYS.Python).Bytes(crypto.sign(key, pContent, "sha256"))
	// create the CMS file
		// creation of tContentInfoDict dictionary
		set tContentInfoDict = builtins.dict()
		do tContentInfoDict."__setitem__"("content_type", "signed_data")
			set tSignedDataDict = builtins.dict()
			do tSignedDataDict."__setitem__"("version", "v3")
				set tAlgoList =  builtins.list()
					set tDigestAlgorithmDict = builtins.dict()
					do tDigestAlgorithmDict."__setitem__"("algorithm", "sha256")
				do tAlgoList.append(cms.DigestAlgorithm(tDigestAlgorithmDict))
			do tSignedDataDict."__setitem__"("digest_algorithms", tAlgoList)
				set tEncapContentInfoDict = builtins.dict()
				do tEncapContentInfoDict."__setitem__"("content_type", "data")
				do tEncapContentInfoDict."__setitem__"("content",  ##class(%SYS.Python).Bytes(pContent))
			do tSignedDataDict."__setitem__"("encap_content_info", tEncapContentInfoDict)
				set tCertList = builtins.list()
				do tCertList.append(cert)
			do tSignedDataDict."__setitem__"("certificates", tCertList)
				set tSignerInfosList = builtins.list()
					set tSignerInfoDict = builtins.dict()
					do tSignerInfoDict."__setitem__"("version", "v3")			
						set tIssuerAndSerialNumberDict = builtins.dict()
						do tIssuerAndSerialNumberDict."__setitem__"("serial_number", (cert."serial_number"))
						do tIssuerAndSerialNumberDict."__setitem__"("issuer", (cert.issuer))
					do tSignerInfoDict."__setitem__"("sid", cms.IssuerAndSerialNumber(tIssuerAndSerialNumberDict))
						set tDigestAlgorithmDict = builtins.dict()
						do tDigestAlgorithmDict."__setitem__"("algorithm", "sha256")
					do tSignerInfoDict."__setitem__"("digest_algorithm", cms.DigestAlgorithm(tDigestAlgorithmDict))
						set tSignedDigestAlgorithmDict = builtins.dict()
						do tSignedDigestAlgorithmDict."__setitem__"("algorithm", "rsassa_pkcs1v15")
					do tSignerInfoDict."__setitem__"("signature_algorithm", cms.SignedDigestAlgorithm(tSignedDigestAlgorithmDict))
					do tSignerInfoDict."__setitem__"("signature",  signature)
				do tSignerInfosList.append(cms.SignerInfo(tSignerInfoDict))
			do tSignedDataDict."__setitem__"("signer_infos", tSignerInfosList)
		do tContentInfoDict."__setitem__"("content", cms.SignedData(tSignedDataDict))
	
	set cmsObj = cms.ContentInfo(tContentInfoDict)

	return cmsObj.dump()
}

}
