Class dc.cms.unittests.TestUtils Extends %UnitTest.TestCase
{

ClassMethod TestGetCert()
{
	set tUtils = ##class(dc.cms.Encrypt).%New()
	set tCertFileName = "C:\Users\sdevin\Documents\DEV\iris-pkcs7-util\misc\cert\asip-p12-EL-TEST-ORG-SIGN-20240304-094358.crt.pem"
	set tKeyFileName = "C:\Users\sdevin\Documents\DEV\iris-pkcs7-util\misc\cert\asip-p12-EL-TEST-ORG-SIGN-20240304-094358.key.pem"
	set tPassPhrase = "*************"
	set tContent = ##class(%Stream.FileCharacter).%New()
	$$$ThrowOnError(tContent.LinkToFile("C:\Users\sdevin\Documents\DEV\iris-pkcs7-util\misc\in\test.txt"))

	set tStream = ##class(%Stream.FileBinary).%New()
	do tStream.LinkToFile("C:\Users\sdevin\Documents\DEV\iris-pkcs7-util\misc\out\test.cms")
	$$$ThrowOnError(tUtils.CreateCMSStream(tContent,tCertFileName, tKeyFileName, tPassPhrase, .tStream))
	set tsc = tStream.%Save()
}

ClassMethod testDev()
{
}

}
