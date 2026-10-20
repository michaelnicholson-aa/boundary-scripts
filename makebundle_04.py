#!/usr/bin/env python3


from cryptography.hazmat.backends  import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509.extensions import ExtensionOID
import argparse
import zipfile
import pdb
import csv
import re
import os


parser = argparse.ArgumentParser(description="Spits out txt file combinations of DOD/ECA zip contents")
parser.add_argument("-v", "--verbose", help="Verbose", action="store_true")
parser.add_argument("-d", "--dod", help="Path to DOD zip file", required=True)
parser.add_argument("-e", "--eca", help="Path to ECA zip file", required=True)
args = parser.parse_args()

dod_dict = {}
if args.dod:
    dod_zip = args.dod

    if os.path.exists(dod_zip):
        if os.path.isfile(dod_zip):
            try:
                z = zipfile.ZipFile(dod_zip, mode="r")
            except BaseException as e:
                # catch error
                print("Fatal error unzipping %s" % dod_zip)
                exit()
        for f in z.namelist():
            if f.endswith("_DoD.pem.p7b"):
                dod_p7b = z.read(f)
    else:
        print("Invalid path:\t%s" % dod_zip)
        exit()
    
    dod_certs = pkcs7.load_pem_pkcs7_certificates(dod_p7b)
    # Already know these are all DoD -- Separate into Root, ID, SW, EMAIL
    for cert in dod_certs:
        ski = ''
        aki = ''
        subject_name = ''
        issuer_name = ''
        ski = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
        try: 
            aki = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex()
        except x509.extensions.ExtensionNotFound as e:
            aki = ''
        issuer_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        dod_dict[str(ski)] = {}
        dod_dict[str(ski)]['subject_name'] = str(subject_name)
        dod_dict[str(ski)]['issuer_name'] = str(issuer_name)
        dod_dict[str(ski)]['cert_data'] = cert
        dod_dict[str(ski)]['fingerprint'] = cert.fingerprint(hashes.SHA256())
        dod_dict[str(ski)]['organization'] = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        dod_dict[str(ski)]['org_type'] = ''
        dod_dict[str(ski)]['cert_policies'] = ''
        dod_dict[str(ski)]['ski'] = str(ski)
        dod_dict[str(ski)]['aki'] = str(aki)
        try:
            dod_dict[str(ski)]['country'] = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        except:
            # country code not set or available -- move on. We know these are US.
            dod_dict[str(ski)]['country'] = 'US'
        #if issuer_name == subject_name:
        if ski == aki:
            dod_dict[str(ski)]['type'] = 'Root'
        elif subject_name == issuer_name:
            dod_dict[str(ski)]['type'] = 'Root'
        elif ' EMAIL ' in subject_name:
            dod_dict[str(ski)]['type'] = 'EMAIL'
        elif ' ID ' in subject_name:
            dod_dict[str(ski)]['type'] = 'ID'
        elif ' SW ' in subject_name:
            dod_dict[str(ski)]['type'] = 'SW'
        else:
            dod_dict[str(ski)]['type'] = None
    
        # Get PEM format of cert
        dod_dict[str(ski)]['certificate'] = dod_dict[str(ski)]['cert_data'].public_bytes(serialization.Encoding.PEM)
# Begin ECA evaluation
eca_dict = {}
if args.eca:
    eca_zip = args.eca
    eca_files = []
    eca_certs = []
    if os.path.exists(eca_zip):
        if os.path.isfile(eca_zip):
            try:
                # attempt to unzip
                z = zipfile.ZipFile(eca_zip, mode="r")
            except:
                # catch error
                if args.verbose:
                    print('debug: exception caught')
        try:
        # Look for all ".cer" files
            for f in z.namelist():
                if f.endswith('.cer'):
                        eca_files.append(z.read(f))
        except BaseException as e:
            if args.verbose:
                print("DEBUG:\n%s" % e)
                exit()
    else:
        print("Invalid path:\t%s" % eca_zip)
        exit()
    for cert in eca_files:
        try:
            eca_certs.append(x509.load_pem_x509_certificate(cert, default_backend()))
        except ValueError as e:
            eca_certs.append(x509.load_der_x509_certificate(cert, default_backend()))
        except BaseException as e:
            print(e)
            print(cert)
            pdb.set_trace()
        continue
    passcounter = 0
    passed_certs = []
    checkthese = []
    for cert in eca_certs:
        ski = ''
        aki = ''
        issuer_name = ''
        subject_name = ''
        # Get Issuer
        try:
            issuer_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[-1].value
        except IndexError:
            try:
                 issuer_name = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[-1].value
            except IndexError:
                 try:
                     issuer_name = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                 except IndexError:
                     # Identify more fields for issuer if we fail in this block
                     passed_certs.append(cert)
                     continue
        # Get Subject
        try:
            subject_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[-1].value
            if 'dhs' in subject_name.lower():
                print(f"miketest1 - {subject_name}")
        except IndexError:
            try:
                subject_name = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[-1].value
            except IndexError:
                # Identify more fields for subject if we fail in this block
                passed_certs.append(cert)
                continue
        try:
            aki = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value.key_identifier.hex()
        except x509.extensions.ExtensionNotFound as e:
            aki = ''
            pass
    
        ski = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER).value.digest.hex()
        # Create Dict entry
        eca_dict[str(ski)] = {}
        eca_dict[str(ski)]['subject_name'] = str(subject_name)
        eca_dict[str(ski)]['issuer_name'] = str(issuer_name)
        eca_dict[str(ski)]['cert_data'] = cert
        eca_dict[str(ski)]['fingerprint'] = cert.fingerprint(hashes.SHA256())
        eca_dict[str(ski)]['type'] = ''
        eca_dict[str(ski)]['ski'] = str(ski)
        eca_dict[str(ski)]['aki'] = str(aki)
        # Get Subject's Organization (if possible) - should issuer org be referenced if this doesn't exist?
        try:
            eca_dict[str(ski)]['organization'] = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value
        except IndexError:
            if len(cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)) == 0:
                eca_dict[str(ski)]['organization'] = 'Undetermined'
        # Get country (if possible) - should issuer country be referenced if this doesn't exist?
        try:
            eca_dict[str(ski)]['country'] = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value
        except IndexError:
            if len(cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)) == 0:
                eca_dict[str(ski)]['country'] = 'Undetermined'
        # Get PEM format of cert
        eca_dict[str(ski)]['certificate'] = eca_dict[str(ski)]['cert_data'].public_bytes(serialization.Encoding.PEM)
    # This block needs work. Need to distinguish between foreign and US ECAs. Not all certs have OID COUNTRY_NAME set properly.
    delete_from_eca = []
    for item in eca_dict.keys():
        if eca_dict[item]['ski'] == eca_dict[item]['aki']:
            eca_dict[item]['type'] = 'ROOT'
        elif eca_dict[item]['subject_name'] == eca_dict[item]['issuer_name']:
            eca_dict[item]['type'] = 'ROOT'
        eca_hash =  eca_dict[item]['cert_data'].fingerprint(hashes.SHA256()) 
        if args.dod:
            for d_item in dod_dict.keys():
                dod_hash = dod_dict[d_item]['cert_data'].fingerprint(hashes.SHA256())
                if eca_hash == dod_hash: #print("debug: removing %s from eca_dict" % item)
                    if args.verbose:
                        print("debug: Already present in dod dict. Removing %s from eca_dict" % item)
                    delete_from_eca.append(item)
                    break
    for item in delete_from_eca:
        if item in eca_dict.keys():
            del eca_dict[item]
# Update dict metadata 
cert_dicts = (dod_dict, eca_dict)
for cert_dict in cert_dicts:
    for key in cert_dict.keys():
        ski = key
        cert_dict[str(ski)]['org_type'] = ''
        cert_dict[str(ski)]['cert_policies'] = ''
        cert = cert_dict[str(ski)]['cert_data']
        try:
            a = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES).__dict__['_value'].__dict__
            # a['_policies'] should be a list of policy objects
            for pol in a['_policies']:
                pol_string = str(pol.policy_identifier.dotted_string)
                cert_dict[str(ski)]['cert_policies'] += str(pol_string + "|")
                if pol_string.startswith('1.3.6.1.4.1.'):
                    cert_dict[str(ski)]['org_type'] = 'Internet Private - Non-Federal'
                    break
                elif pol_string.startswith('1.3.6.'):
                    cert_dict[str(ski)]['org_type'] = 'DoD'
                    if cert_dict[str(ski)]['country'] == '' or cert_dict[str(ski)]['country'].lower() == "undetermined":
                        cert_dict[str(ski)]['country'] = "US"
                        break
                elif pol_string.startswith('2.16.840.1.101.2.') or pol_string.startswith('1.3.6.'):
                    cert_dict[str(ski)]['org_type'] = 'DoD'
                    if cert_dict[str(ski)]['country'] == '' or cert_dict[str(ski)]['country'].lower() == "undetermined":
                        cert_dict[str(ski)]['country'] = "US"
                        break
                elif pol_string.startswith('2.16.840.1.101.3.'):
                    cert_dict[str(ski)]['org_type'] = 'Federal Non-DoD'
                    if cert_dict[str(ski)]['country'] =='' or cert_dict[str(ski)]['country'].lower() == "undetermined":
                        cert_dict[str(ski)]['country'] = "US"
                        break
                elif pol_string.startswith('2.16.840.'):
                    cert_dict[str(ski)]['org_type'] = 'US'
                    if cert_dict[str(ski)]['country'] == '' or cert_dict[str(ski)]['country'].lower() == "undetermined":
                        cert_dict[str(ski)]['country'] = "US"
                        break
                elif pol_string.startswith('2.16.'):
                    cert_dict[str(ski)]['org_type'] = 'Foreign'
                    break
                elif pol_string.startswith('1.2.840'):
                    cert_dict[str(ski)]['org_type'] = 'US'
                    if cert_dict[str(ski)]['country'] == '' or cert_dict[str(ski)]['country'].lower() == "undetermined":
                        cert_dict[str(ski)]['country'] = "US"
                        break
                elif pol_string.startswith('1.2.'):
                    cert_dict[str(ski)]['org_type'] = 'Foreign'
        except BaseException as e:
            cert_dict[str(ski)]['org_type'] = 'No certificate policy extension found'
            # Move to next cert
            pass

        # If no policies could determine country and it is still not set, look at subject names...
        if cert_dict[str(ski)]['country'] == '' or cert_dict[str(ski)]['country'].lower() == 'undetermined':
            if 'raytheon' in subject_name.lower():
                cert_dict[str(ski)]['org_type'] = 'US'
                cert_dict[str(ski)]['country'] = 'US'
            elif 'u.s. department of state' in subject_name.lower():
                cert_dict[str(ski)]['country'] = 'US'
            elif 'exostar' in subject_name.lower():
                cert_dict[str(ski)]['country'] = 'US'

f = open('miketest.csv', 'w+')
csv_writer = csv.DictWriter(f, fieldnames = ['subject_name', 'issuer_name','type', 'organization', 'org_type', 'country', 'cert_policies', 'cert_data', 'fingerprint', 'certificate', 'ski', 'aki'])
csv_writer.writeheader()
for d in eca_dict.keys():
    csv_writer.writerow(eca_dict[d])

# US ECAs
us_eca_only = {}
us_eca_only['name'] = 'us_eca_only'
us_eca_only['certs'] = [eca_dict[cert]['certificate'] for cert in eca_dict.keys() if eca_dict[cert]['country'] == 'US']
with open(str(us_eca_only['name'] + '.txt'), 'w+') as ECA_US:
    for cert in us_eca_only['certs']:
        ECA_US.write(cert.decode())

# AU ECAs
au_eca_only = {}
au_eca_only['name'] = 'au_eca_only'
au_eca_only['certs'] = [eca_dict[cert]['certificate'] for cert in eca_dict.keys() if eca_dict[cert]['country'] == 'AU']
with open(str(au_eca_only['name'] + '.txt'), 'w+') as ECA_AU:
        for cert in au_eca_only['certs']:
                    ECA_AU.write(cert.decode())

# Foreign/Undetermined ECAs
foreign_eca_only = {}
foreign_eca_only['name'] = 'foreign_eca_only'
foreign_eca_only['certs'] = [eca_dict[cert]['certificate'] for cert in eca_dict.keys() if not eca_dict[cert]['country'] == 'US']
with open(str(foreign_eca_only['name'] + '.txt'), 'w+') as ECA_FOREIGN:
    for cert in foreign_eca_only['certs']:
        ECA_FOREIGN.write(cert.decode())

# All ECA

all_eca = {}
all_eca['name'] = 'all_eca'
all_eca['certs'] = [eca_dict[cert]['certificate'] for cert in eca_dict.keys()]
with open(str(all_eca['name'] + '.txt'), 'w+') as ECA_ALL:
    for cert in all_eca['certs']:
        ECA_ALL.write(cert.decode())

#DOD ID ONLY
dod_id_only = {}
dod_id_only['name'] = 'dod_id_only'
dod_id_only['certs'] = [dod_dict[cert]['certificate'] for cert in dod_dict.keys() if dod_dict[cert]['type'] == 'ID']
with open(str(dod_id_only['name'] + '.txt'), 'w+') as DOD_ID:
    for cert in dod_id_only['certs']:
        DOD_ID.write(cert.decode())

#DOD SW ONLY
dod_sw_only = {}
dod_sw_only['name'] = 'dod_sw_only'
dod_sw_only['certs'] = [dod_dict[cert]['certificate'] for cert in dod_dict.keys() if dod_dict[cert]['type'] == 'SW']
with open(str(dod_sw_only['name'] + '.txt'), 'w+') as DOD_ID:
    for cert in dod_sw_only['certs']:
        DOD_ID.write(cert.decode())

#DOD Roots ONLY
dod_roots_only = {}
dod_roots_only['name'] = 'dod_roots_only'
dod_roots_only['certs'] = [dod_dict[cert]['certificate'] for cert in dod_dict.keys() if dod_dict[cert]['type'] == 'Root']
with open(str(dod_roots_only['name'] + '.txt'), 'w+') as DOD_ROOTS:
    for cert in dod_roots_only['certs']:
        DOD_ROOTS.write(cert.decode())

#DOD Email ONLY
dod_email_only = {}
dod_email_only['name'] = 'dod_email_only'
dod_email_only['certs'] = [dod_dict[cert]['certificate'] for cert in dod_dict.keys() if dod_dict[cert]['type'] == 'EMAIL']
with open(str(dod_email_only['name'] + '.txt'), 'w+') as DOD_EMAIL:
        for cert in dod_email_only['certs']:
            DOD_EMAIL.write(cert.decode())

dod_derility_only = {}
dod_derility_only['name'] = 'dod_derility_only'
dod_derility_only['certs'] = [dod_dict[cert]['certificate'] for cert in dod_dict.keys() if 'derility' in dod_dict[cert]['subject_name'].lower()]
with open(str(dod_derility_only['name'] + '.txt'), 'w+') as DOD_DERILITY:
    for cert in dod_derility_only['certs']:
        DOD_DERILITY.write(cert.decode())
