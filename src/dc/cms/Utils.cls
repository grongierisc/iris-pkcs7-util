Class dc.cms.Utils Extends %RegisteredObject
{

XData %import [ MimeType = application/python ]
{
import iris
from asn1crypto import cms,x509,pem
from OpenSSL import crypto
from datetime import datetime,timezone
}

Method CreateCMSStream(pContent As %Library.CharacterStream, pCertFileName As %String, pKeyFileName As %String, pPassword As %String, Output pResult As %Library.CharacterStream) As %Status
{
    Set tSC = $$$OK
    // Convert the content to bytes
    Set tContentBytes = ..ConvertStreamToString(pContent)
    set tResultBytes = ..GenerateCMS(tContentBytes,pCertFileName,pKeyFileName,pPassword)
    // Convert the result to a stream
    Set pResult = ..ConvertStringToStream(tResultBytes)
    Quit tSC
}

Method ConvertStreamToString(pStream As %Library.CharacterStream) [ Language = python ]
{
    tString = ''
    while pStream.AtEnd == 0:
        tString += pStream.Read(32767)
    # convert to bytes
    return tString
}

Method ConvertStringToStream(pString) As %Library.CharacterStream [ Language = python ]
{
    # convert to string
    tString = pString
    # convert to stream
    stream = iris.cls('%Stream.GlobalCharacter')._New()
    n = 32767
    chunks = [tString[i:i+n] for i in range(0, len(tString), n)]
    for chunk in chunks:
        stream.Write(chunk)
    stream.Rewind()
    return stream
}

Method "load_certificates"(certfilename) As %String [ Language = python ]
{
    with open(certfilename, 'rb') as f:
        der_bytes = f.read()
        if pem.detect(der_bytes):
            _, _, der_bytes = pem.unarmor(der_bytes)
        cert = x509.Certificate.load(der_bytes)
    return cert
}

Method "load_private_key"(keyfilename, keypassword) As %String [ Language = python ]
{
    # load the private key
    with open(keyfilename, 'rb') as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), keypassword.encode('utf-8'))
    return key
}

Method "certificate_date_check"(cert) As %String [ Language = python ]
{

    # validate the certificate
    if cert.not_valid_before > datetime.now(tz=timezone.utc):
        raise Exception('Certificate not valid yet')
    if cert.not_valid_after < datetime.now(tz=timezone.utc):
        raise Exception('Certificate expired')
}

Method "certificate_usage_check"(cert) As %String [ Language = python ]
{
    # validate the certificate
    if cert.key_usage_value and 'digital_signature' not in cert.key_usage_value.native:
        raise Exception('Certificate not allowed for digital signature')
}

Method GenerateCMS(content, certfilename, keyfilename, keypassword) As %String [ Language = python ]
{
    # load the certificate
    cert = self.load_certificates(certfilename)

    # validate the certificate
    self.certificate_date_check(cert)
    self.certificate_usage_check(cert)

    # load the private key
    key = self.load_private_key(keyfilename, keypassword)

    # sign the content
    signature = crypto.sign(key, content, 'sha256')

    # create the CMS file
    cms_obj = cms.ContentInfo({
        'content_type': 'signed_data',
        'content': cms.SignedData({
            'version': 'v3',
            'digest_algorithms': [
                cms.DigestAlgorithm({'algorithm': 'sha256'}),
            ],
            'encap_content_info': {
                'content_type': 'data',
                'content': bytes(content,'utf-8'),
            },
            'certificates': [cert],
            'signer_infos': [
                cms.SignerInfo({
                    'version': 'v3',
                    'sid': cms.IssuerAndSerialNumber({
                        'issuer': cert.issuer,
                        'serial_number': cert.serial_number,
                    }),
                    'digest_algorithm': cms.DigestAlgorithm({'algorithm': 'sha256'}),
                    'signature_algorithm': cms.SignedDigestAlgorithm({'algorithm': 'rsassa_pkcs1v15'}),

                    # sign the content

                    'signature': signature,
                    
                }),

            ],

        }),
    })
    
    return cms_obj.dump()
}

}
