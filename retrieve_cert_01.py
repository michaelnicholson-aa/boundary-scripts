#!/usr/bin/env python3

import re
import pdb
import random
import logging
import argparse
import requests
import cryptography
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.hazmat.backends  import default_backend
from cryptography.x509.oid import ExtensionOID

def main():

    parser = argparse.ArgumentParser(description="Retrieve CSRs from CA-82")
    parser.add_argument("-v", "--verbose", help="Enables verbose logging - very chatty!", action="store_true")
    parser.add_argument("-r", "--requestid", help="CertID to be retrieved", required=True)
    parser.add_argument("-n", "--randomno", help="Add random number to filename", required=False)
    args = parser.parse_args()

    # Set up Logging
    logger = get_logger(__name__)
    if args.verbose:
        loglevel = logging.DEBUG
        logger.setLevel(loglevel)
        logging.getLogger("mike_f5").setLevel(loglevel)
        logger.log(logging.DEBUG, "Debugging enabled.")
    else:
        loglevel = logging.INFO
        logger.setLevel(loglevel)
    cn, cert, pkcs7 = retrieve_cert(args.requestid)
    write_cert(cn, cert, pkcs7, args)

def retrieve_cert(req_id):

    logger = get_logger(__name__)

    #proxies = {"http": "http://proxy.some.domain.com:8080", "https": "http://proxy.some.domain.com:8443"}
    conn = requests.session()
    # url is https://someCA-XX.some.domain.com/ca/ee/ca/checkRequest?requestId=<id>
    req_url = "https://someCA-XX.some.domain.com/ca/ee/ca/checkRequest?requestId="
    # Just making sure no trailing whitespace on number
    req_url = req_url + req_id.rstrip()
    logger.log(logging.DEBUG, str("Request URL: %s" % req_url))
    resp = conn.get(req_url)

    '''
    Response will have serial number listed in this line:

    record.serialNumber="14c05";

    Use this value to look up by serial
    '''
    if resp.status_code != 200:
        logger.log(logging.CRITICAL, str("Error during HTTP request - URL:%s" % req_url))
        exit(1)
    logger.log(logging.DEBUG, str("HTTP Code: %s" % resp.status_code))
    pending_pat = re.compile(r'header.status = "pending";')
    #serial_pat = re.compile(r'(record.serialNumber=")(.*)(";)')
    serial_pat = re.compile(r'(record.serialNumber=")([a-fA-F0-9]{1,6})(";)')
    #pdb.set_trace()
    mo = re.findall(serial_pat, str(resp.content))
    if not mo:
        mo = re.findall(pending_pat, str(resp.content))
        if mo:
            logger.log(logging.WARNING, str("Request %s is in pending status. Exiting..." % req_id))
            exit(0)
        else:
            logger.log(logging.CRITICAL, str("Serial number not found! Exiting..."))
            exit(1)
    logger.log(logging.DEBUG, mo)
    '''
    [('record.serialNumber="', '14c05', '";')]
    mo[0][1]
    '14c05'
    '''
    serial = mo[0][1]

    # url is https://someCA-XX.some.domain.com/ca/ee/ca/displayBySerial?serialNumber=0x<serial>

    '''
    Response will have cert data listed in this line:

    header.certChainBase64 = "MII...;
   
    B64 data contains carriage returns and new lines. Line always ends with semicolon.
    Will have to add BEGIN/END Certificate tags manually
    '''
    cert_url = "https://someCA-XX.some.domain.com/ca/ee/ca/displayBySerial?serialNumber=0x"
    cert_url = cert_url + serial
    logger.log(logging.DEBUG, str("Cert URL: %s" % cert_url))
    resp = conn.get(cert_url)
    logger.log(logging.DEBUG, str("HTTP Code: %s" % resp.status_code))
    cert_pat = re.compile(r'(header.certChainBase64 = ")(.*?)(";)')
    pkcs7_pat = re.compile(r'(header.pkcs7ChainBase64 = ")(.*?)(";)')
    mo = re.findall(cert_pat, str(resp.content))
    mo2 = re.findall(pkcs7_pat, str(resp.content))
    #pdb.set_trace()
    cert = mo[0][1]
    pkcs7 = mo2[0][1]
   #pdb.set_trace()
    cert = cert.replace("\\\\r\\\\n", "\n")
    pkcs7 = pkcs7.replace("\\\\r\\\\n", "\n")
    cert = cert.replace("\\", "")
    pkcs7 = pkcs7.replace("\\", "")
    cert = '-----BEGIN CERTIFICATE-----\n' + cert
    cert = cert + '-----END CERTIFICATE-----'
    pkcs7 = '-----BEGIN PKCS7-----\n' + pkcs7
    pkcs7 = pkcs7 + '-----END PKCS7-----'
    xcert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
    cn = str(xcert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    #cn = xcert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    logger.log(logging.DEBUG, str("CN: %s, Serial: %s" % (cn, xcert.serial_number)))
    return cn, cert, pkcs7

def write_cert(cn, cert, pkcs7, args):
    logger = get_logger(__name__)
    num = random.randint(1,65535)
    if args.randomno:
        with open(str(f"{cn}{num}.crt"), "w") as CERTFILE:
            CERTFILE.write(cert)
        logger.log(logging.INFO, str(f"Wrote to file: {cn}{num}.crt"))
        with open(str(f"{cn}{num}.pkcs7"), "w") as PKCS7FILE:
            PKCS7FILE.write(pkcs7)
        logger.log(logging.INFO, str(f"Wrote to file: {cn}{num}.pkcs7"))
        exit(0)
    else:
        with open(str(f"{cn}.crt"), "w") as CERTFILE:
            CERTFILE.write(cert)
        logger.log(logging.INFO, str(f"Wrote to file: {cn}.crt"))
        with open(str(f"{cn}.pkcs7"), "w") as PKCS7FILE:
            PKCS7FILE.write(pkcs7)
        logger.log(logging.INFO, str(f"Wrote to file: {cn}.pkcs7"))
        exit(0)

def get_logger(name):

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logfile = logging.FileHandler('retrieve_cert.log')
        # Always log debug to file whether selected or not
        logfile.setLevel(logging.DEBUG)
        logger.addHandler(console)
        logger.addHandler(logfile)
        c_format = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')
        console.setFormatter(c_format)
        logfile.setFormatter(c_format)
    return logger
    

if __name__ == "__main__":

    main()
