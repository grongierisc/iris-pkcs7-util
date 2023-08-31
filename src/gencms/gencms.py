# with asn1crypto generate an CMS file with a signed data content type
# create a function that will generate a CMS file
# input parameters are:
# - the content to sign as an filename
# - the certificate to use as an filename
# - the private key to use as an filename
# - the output filename

from asn1crypto import cms,x509,pem
from OpenSSL import crypto
from datetime import datetime,timezone

def load_certificates(cert_filename):
    # load the certificate
    with open(cert_filename, 'rb') as f:
        der_bytes = f.read()
        if pem.detect(der_bytes):
            _, _, der_bytes = pem.unarmor(der_bytes)
        cert = x509.Certificate.load(der_bytes)
    return cert

def load_private_key(key_filename, key_password):
    # load the private key
    with open(key_filename, 'rb') as f:
        key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read(), key_password)
    return key

def certificate_date_check(cert):
    # validate the certificate
    if cert.not_valid_before > datetime.now(tz=timezone.utc):
        raise Exception('Certificate not valid yet')
    if cert.not_valid_after < datetime.now(tz=timezone.utc):
        raise Exception('Certificate expired')
    
def certificate_usage_check(cert):
    # validate the certificate
    if cert.key_usage_value and 'digital_signature' not in cert.key_usage_value.native:
        raise Exception('Certificate not allowed for digital signature')

def generate_cms_bytes(content_bytes,cert_filename, key_filename, key_password):
    # load the certificate
    cert = load_certificates(cert_filename)

    # validate the certificate
    certificate_date_check(cert)
    certificate_usage_check(cert)

    # load the private key
    key = load_private_key(key_filename, key_password)

    # sign the content
    signature = crypto.sign(key, content_bytes, 'sha256')

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
                'content': content,
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


def generate_cms_file(content_filename, cert_filename, key_filename, key_password, output_filename):
    # load the content to sign
    with open(content_filename, 'rb') as f:
        content = f.read()

    # load the certificate
    cert = load_certificates(cert_filename)

    # validate the certificate
    certificate_date_check(cert)
    certificate_usage_check(cert)

    # load the private key
    key = load_private_key(key_filename, key_password)

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
                'content': content,
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

    # write the CMS file
    with open(output_filename, 'wb') as f:
        f.write(cms_obj.dump())

    return output_filename


if __name__ == '__main__':
    # test
    path = '/Users/grongier/git/iris-pkcs7-util/'
    content = '/Users/grongier/git/iris-pkcs7-util/misc/in/NORMEDRE_300356-840001861_20181_25-1_20190326175624.txt'
    cert = '/Users/grongier/git/iris-pkcs7-util/misc/cert/asip-p12-EL-TEST-ORG-SIGN-20200702-170758.crt.pem'
    key = '/Users/grongier/git/iris-pkcs7-util/misc/key/asip-p12-EL-TEST-ORG-SIGN-20200702-170758.key.pem'
    cms_file = '/Users/grongier/git/iris-pkcs7-util/misc/out/cms_file.cms'

    generate_cms_file(content, cert, key, b'InterSystems2020!', cms_file)