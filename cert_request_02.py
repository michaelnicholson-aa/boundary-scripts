#!/usr/bin/env python3

import os
import re
import pdb
import urllib
import logging
import requests
import argparse
import ipaddress
import subprocess
from cryptography import x509
from cryptography.x509 import NameOID
from cryptography.x509 import load_pem_x509_csr
from cryptography.hazmat.backends  import default_backend
from cryptography.x509.oid import ExtensionOID



# Heavily plagiarized from Adam Orwig cert_request.ps1
# csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value[0].value


def main():
    parser = argparse.ArgumentParser(description="Submits CSRs to CA-XX")
    parser.add_argument("-v", "--verbose", help="Enables verbose logging - very chatty!", action="store_true")
    parser.add_argument("-c", "--csrfile", help="CSR(s) to be uploaded", required=True, nargs="*")
    parser.add_argument("-e", "--emailaddress", help="Valid .mil address to submit/receive request", required=True)
    parser.add_argument("-p", "--phone", help="Phone number required for submission", required=True)
    args = parser.parse_args()

    logger = get_logger(__name__)
    if args.verbose:
        loglevel = logging.DEBUG
        logger.setLevel(loglevel)
        logger.log(logging.DEBUG, "Debugging enabled.")
    else:
        loglevel = logging.INFO
        logger.setLevel(loglevel)
    csr_submissions = []
    for csrfile in args.csrfile:
        errorcode, html, req_info = submitCSR(csrfile, args.emailaddress, args.phone, logger)
        csr_submissions.append(req_info)
    # each req_info is a dict with keys cn and req_id. add each of these to a list so we can send all in same email
    write_email(csr_submissions=csr_submissions)
    send_email()
    #send_email(src_email=args.emailaddress, dst_email="removed@some.domain.com", req_info=csr_submissions)

def get_logger(name):

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logfile = logging.FileHandler('cert_request.log')
        # Always log debug to file whether selected or not
        logfile.setLevel(logging.DEBUG)
        logger.addHandler(console)
        logger.addHandler(logfile)
        c_format = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')
        console.setFormatter(c_format)
        logfile.setFormatter(c_format)
    return logger

def submitCSR(csrfile, emailaddress, phone, logger):

    logger = get_logger(__name__)
    ca_url = "https://someCA-XX.some.domain.com/ca/ee/ca/profileSubmit"
    #proxies = {"http": "http://proxy.some.domain.com:8080", "https": "http://proxy.some.domain.com:8443"}
    if not os.path.exists(csrfile):
        logger.log(logging.CRITICAL, str("Unable to locate %s" % csrfile))
    with open(csrfile, 'r') as CSR_TEXT:
        csrtext = CSR_TEXT.read()
        csr = load_pem_x509_csr(csrtext.encode(), default_backend())
    # Check for SANs
    #pdb.set_trace()
    cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    try:
        csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = [san.value for san in csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value]
        logger.log(logging.DEBUG, str("SANS: %s" % sans))
    except BaseException as e:
        logger.log(logging.INFO, "No SANS found")
    payload = {}
    payload["cert_request"] = csrtext
    payload["cert_request_type"] = "pkcs10"
    try:
        assert(sans)
        if sans:
            for index, value in enumerate(sans):
                t = index + 1
                try:
                    assert(ipaddress.IPv4Address(value))
                    payload[str("gnameType%s" % t)] = "IPAddress"
                    payload[str("gnameValue%s" % t)] = value.compressed
                except ipaddress.AddressValueError as e:
                    payload[str("gnameType%s" % t)] = "DNSName"
                    payload[str("gnameValue%s" % t)] = value
        else:
            payload["gnameType1"] = "DNSName"
            payload["gnameValue1"] = cn
    except:
        pass
    name = emailaddress.split("@")[0].replace(".", " ")
    name = name.replace(" civ", "")
    name = name.replace(" ctr", "")
    payload["requestor_name"] = name
    payload["requestor_email"] = emailaddress
    payload["requestor_phone"] = phone
    payload["profileId"] = "caMultiSanEKU"
    payload["renewal"] = "false"
    payload["xmlOutput"] = "false"
    # payload = python dict -- need to encode 
    #pdb.set_trace()
    payload = urllib.parse.urlencode(payload)
    # Thanks again, Adam. Not removing the newline causes HTTP 400 Bad Request errors.
    payload = payload.replace('-----END+CERTIFICATE+REQUEST-----%0A', '-----END+CERTIFICATE+REQUEST-----')
    logger.log(logging.DEBUG, (payload))
    #pdb.set_trace()
    # Open connection
    conn = requests.session()
    conn.headers.update({"Content-Type": "application/x-www-form-urlencoded"})
    #resp = conn.post(ca_url, data=payload, proxies=proxies)
    resp = conn.post(ca_url, data=payload)
    conn.close()
    pat = re.compile(r"(requestList.requestId=\")([\d]+)\"")
    # Get request ID
    # Match looks like [('requestList.requestId="', '92461')]
    try:
        req_id = re.findall(pat, str(resp.content))[0][-1]
    except IndexError as e:
        print(e)
        if 'forbidden' in resp.content.decode().lower():
            logger.log(logging.WARNING, str("Submission of %s failed with response 'Forbidden'. Skipping CSR..." % csrfile))
        #pdb.set_trace()
        return resp.status_code, str(resp.content), {"cn": cn, "req_id": "Forbidden"}
    #req_id = "12345667"
    #resp_code = "200"
    #str(resp.content) = "asdf"
    logger.log(logging.INFO, str("Received ReqID: %s for %s" % (req_id,cn)))
    return resp.status_code, str(resp.content), {"cn": cn, "req_id": req_id}
    #return resp_code, str(resp.content), {"cn": cn, "req_id": req_id}

def write_email(src_email="removed@some.domain.com", dst_email="removed2@some.domain.com", csr_submissions=[]):
    with open("email.txt", "w+") as EMAIL:
        EMAIL.write("")
    body_hdr = str("Please approve below requests:\n\n")
    with open("email.txt", "w+") as EMAIL:
        EMAIL.write(body_hdr)
        for req in csr_submissions:
            print(req)
            EMAIL.write(str("CA: XX\nCN: %s\nRequest ID: %s\n\n" % (req["cn"], req["req_id"])))

def send_email():
    with open("email.txt", "r") as EMAIL:
        email_contents = EMAIL.read()
        e = subprocess.Popen(["cat", "email.txt"], stdout=subprocess.PIPE)  
        m = subprocess.Popen(["mail", "-v", "-s", "Certificate Request(s) (CA-XX)", "removed@some.domain.com"], stdin=e.stdout, stdout=subprocess.PIPE)


if __name__ == "__main__":

    main()
