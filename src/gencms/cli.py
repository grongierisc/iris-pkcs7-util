# module to create the cli interface for the application

import argparse
import sys

from gencms.gencms import generate_cms_file

def main():
    parser = argparse.ArgumentParser(description='Generate a CMS file')
    parser.add_argument('content_filename', help='the file to sign')
    parser.add_argument('cert_filename', help='the certificate to use')
    parser.add_argument('key_filename', help='the private key to use')
    parser.add_argument('key_password', help='the private key password')
    parser.add_argument('output_filename', help='the output CMS file')
    args = parser.parse_args()

    # cconvert string to bytes
    args.key_password = args.key_password.encode('utf-8')
    generate_cms_file(args.content_filename, args.cert_filename, args.key_filename, args.key_password, args.output_filename)