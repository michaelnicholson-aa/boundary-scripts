#!/usr/bin/env python3


# For reference - list of unicode objects must be used to add SANs
# Supports multiple lines to allow multiple SAN certs to be created 
san_list = ['basecn.some.domain.com', 'san1.some.domain.com', 'san2.some.domain.com', 'san3.some.domain.com']

from cryptography.hazmat.backends  import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from cryptography import x509
from cryptography.x509.oid import NameOID
import argparse
import random
import sys
import pdb

parser = argparse.ArgumentParser()
parser.add_argument("-k", "--keyfile", help="Use keyfile instead of creating one", required=False)
parser.add_argument("-s", "--sanfile", help="Text file with whitespace separated sans per cert", required=True)
args = parser.parse_args()

noread = False
try:
    sanfile = args.sanfile
    f = open(sanfile, 'r')
    #san_lists = [unicode(line.split('\n')[0]) for line in f.readlines()]
    san_lists = []
    for line in f.readlines():
        san_lists.append(line.split('\n')[0])
        if args.keyfile:
            # Exit after first line. Only generating one csr for specified key
            break
except IOError as e:
    noread = True
    pass


for san_list in san_lists: 
    san_list = san_list.split()
    if not args.keyfile:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    else:
        with open(args.keyfile, "rb") as keyfile:
            key = serialization.load_pem_private_key(keyfile.read(), password=None, backend=default_backend())
    
    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
            # subject_name takes 1 x509.Name ARG. This 1 ARG consists of list of 1 or more X509.NameAttributes
            # these can be assigned using the NameOID.<NAME> syntax. All strings have to be unicode (denoted by u'string')
            # jk we're on python3 now
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "USN"),
                x509.NameAttribute(NameOID.COMMON_NAME, san_list[0]),
                # Done with subject_name -- Adding SAN extension to the CSR Builder Object
                     ])).add_extension(
    # x509.SubjectAlternativeName takes 1 or more various X509 Name objects. For now only using X509.DNSName to pack unicode strings into a list
    x509.SubjectAlternativeName([x509.DNSName(san) for san in san_list]),critical=False).sign(key, hashes.SHA256(), default_backend())
    
    # Encodes CSR as PEM
    #pdb.set_trace()
    csr_data = csr.public_bytes(serialization.Encoding.PEM).decode()

    # Encodes pkey bytes as PEM and adds OpenSSL newlines and header/trailer tags -- No encryption on disk
    if not args.keyfile:
        pkey = key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode()
    
    num = random.randint(1,65535)
    csrfile = str(f"{san_list[0]}{num}.csr")
    if not args.keyfile:
        keyfile = str(f"{san_list[0]}{num}.key")
    c = open(csrfile, 'w')
    c.write(csr_data)
    c.close()
    if not args.keyfile:
        k = open(keyfile, 'w')
        k.write(pkey)
        k.close()
    
    if noread:
        print(str('There was an I/O error reading the file specified: [%s]\nCSR and Key were generated using example values:\n%s' % (sanfile,san_list)))
    else:
        c = open(csrfile, 'r')
        print("---------------------------\n")
        print("-----Below is your CSR-----\n")
        print("---------------------------\n")
        print("FOR:\t%s\n" % san_list[0])
        print(str(c.read()))
        c.close()
        if not args.keyfile:
            k = open(keyfile, 'r')
            print("---------------------------")
            print("-----Below is your Key-----")
            print("---------------------------")
            print("FOR:\t%s\n" % san_list[0])
            print(str(k.read()))
            k.close()
    
    
    '''
    C=US, O=U.S. Government, OU=DoD, OU=PKI, OU=DOD, CN=rw2799.some.domain.com
    
     |  DN_QUALIFIER = <ObjectIdentifier(oid=2.5.4.46, name=dnQualifier)>
     |
     |  DOMAIN_COMPONENT = <ObjectIdentifier(oid=0.9.2342.19200300.100.1.25, n...
     |
     |  EMAIL_ADDRESS = <ObjectIdentifier(oid=1.2.840.113549.1.9.1, name=email...
     |
     |  GENERATION_QUALIFIER = <ObjectIdentifier(oid=2.5.4.44, name=generation...
     |
     |  GIVEN_NAME = <ObjectIdentifier(oid=2.5.4.42, name=givenName)>
     |
     |  JURISDICTION_COUNTRY_NAME = <ObjectIdentifier(oid=1.3.6.1.4.1.311.60.2...
     |
     |  JURISDICTION_LOCALITY_NAME = <ObjectIdentifier(oid=1.3.6.1.4.1.311.60....
     |
     |  JURISDICTION_STATE_OR_PROVINCE_NAME = <ObjectIdentifier(oid=1.3.6.1.4....
     |
     |  LOCALITY_NAME = <ObjectIdentifier(oid=2.5.4.7, name=localityName)>
     |
     |  ORGANIZATIONAL_UNIT_NAME = <ObjectIdentifier(oid=2.5.4.11, name=organi...
     |
     |  ORGANIZATION_NAME = <ObjectIdentifier(oid=2.5.4.10, name=organizationN...
     |
     |  POSTAL_ADDRESS = <ObjectIdentifier(oid=2.5.4.16, name=postalAddress)>
     |
     |  POSTAL_CODE = <ObjectIdentifier(oid=2.5.4.17, name=postalCode)>
     |
     |  PSEUDONYM = <ObjectIdentifier(oid=2.5.4.65, name=pseudonym)>
     |
     |  SERIAL_NUMBER = <ObjectIdentifier(oid=2.5.4.5, name=serialNumber)>
     |
     |  STATE_OR_PROVINCE_NAME = <ObjectIdentifier(oid=2.5.4.8, name=stateOrPr...
     |
     |  STREET_ADDRESS = <ObjectIdentifier(oid=2.5.4.9, name=streetAddress)>
     |
     |  SURNAME = <ObjectIdentifier(oid=2.5.4.4, name=surname)>
     |
     |  TITLE = <ObjectIdentifier(oid=2.5.4.12, name=title)>
     |
     |  USER_ID = <ObjectIdentifier(oid=0.9.2342.19200300.100.1.1, name=userID...
     |
     |  X500_UNIQUE_IDENTIFIER = <ObjectIdentifier(oid=2.5.4.45, name=x500Uniq...
    '''

