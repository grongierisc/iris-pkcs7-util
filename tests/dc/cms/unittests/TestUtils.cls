Class dc.cms.unittests.TestUtils Extends %UnitTest.TestCase
{

ClassMethod TestGetCert()
{
	set tUtils = ##class(dc.cms.Utils).%New()
	set tCertFileName = "/home/irisowner/dev/misc/cert/asip-p12-EL-TEST-ORG-SIGN-20200702-170758.crt.pem"
	set tKeyFileName = "/home/irisowner/dev/misc/key/asip-p12-EL-TEST-ORG-SIGN-20200702-170758.key.pem"
	set tPassPhrase = "TOTO"
	set tContent = ##class(%Stream.FileCharacter).%New()
	$$$ThrowOnError(tContent.LinkToFile("/home/irisowner/dev/misc/in/NORMEDRE_300356-840001861_20181_25-1_20190326175624.txt"))


	$$$ThrowOnError(tUtils.CreateCMSStream(tContent,tCertFileName, tKeyFileName, tPassPhrase, .tStream))
	zwrite tStream
}

}
