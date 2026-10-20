#!/usr/bin/python3
import pdb
#from cryptography.hazmat.primitives.asymmetric import r
#from cryptography.hazmat.backends  import default_backend
import logging
import zipfile
import re
import os
import subprocess
import argparse
import threading
#from cryptography import x509

def locate_by_keymod(mod, keymods, bigipconf, filepath):

    # with the modulus find the current matching filesystem path dumped to /shared/tmp/keymods.txt
    try:
        pdb.set_trace()
        modpat = re.compile(fr"(\n.*,)(Modulus=)({mod})")
        mo = re.search(modpat, keymods)
        fspath = mo.groups()[0].lstrip('\n').rstrip(',')
        # Append fspath to modulus_dict key so we can find the loaded BigIP object associated with that fspath
        fspathpat = re.compile(fr"(^.*ssl-cert )(.*)(\s\S$\n)(.*)({fspath})", re.MULTILINE)
        mo = re.search(fspathpat, bigipconf)
        certpath = mo.groups(0)[1]
        print(f"Found {certpath} for {mod}")
    except AttributeError as e:
        pass
    except BaseException as e:
        print(e)
        pdb.set_trace()


def locate_by_certmod(bigipconf, filepath):
    logger = get_logger(__name__)
    logger.setLevel(loglevel)
    try:
        fspath = filepath
        fspathpat = re.compile(fr"(^.*ssl-cert )(.*)(\s\S$\n)(.*)({fspath})", re.MULTILINE)
        mo = re.search(fspathpat, bigipconf)
        certpath = mo.groups(0)[1]
        logger.log(logging.DEBUG, f"Found {certpath} for {fspath}")
        return certpath
    except AttributeError as e:
        pass
    except BaseException as e:
        print(e)
        pdb.set_trace()

def prep_certmods():

    logger = get_logger(__name__)
    logger.setLevel(loglevel)

    # We need to multi-thread or multi-process this. Slow as shit
    # Certs should be a list of fspaths
    certlist = []
    #modsfile = '/shared/tmp/certmods.txt'
    #modsfile = "/home/ldap/mnicholson/certmods.txt"
    certdir = '/config/filestore/files_d/Common_d/certificate_d/'
    #certdir = "/home/ldap/mnicholson/cert_stuff"
    for root, dirs, files in os.walk(certdir):
        for f in files:
            certpath = os.path.join(root,f)
            if not os.path.islink(certpath):
               certlist.append(certpath) 
    joblist1 = certlist[0:len(certlist)//4]
    joblist2 = certlist[len(certlist)//4:len(certlist)//2]
    joblist3 = certlist[len(certlist)//2:(len(certlist)//4)*3]
    joblist4 = certlist[(len(certlist)//4)*3:]
    threads = []
    logger.log(logging.INFO, f"Generating modulus for {len(certlist)} local certificate files...")
    locals_modulus_dict = {}
    for job in joblist1, joblist2, joblist3, joblist4:
        thread = threading.Thread(target=certmod, args=(job,locals_modulus_dict))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
    return locals_modulus_dict
        

def certmod(certs,locals_modulus_dict):
    for certpath in certs:
        try:
            modulus_p = subprocess.Popen(['openssl', 'x509','-modulus', '-noout', '-in', certpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if not modulus_p.wait() == 0:
                continue
            modulus = modulus_p.stdout.read().decode().rstrip('\n').replace("Modulus=", "")
            locals_modulus_dict[certpath] = modulus
        except BaseException as e:
            print(e)
            pdb.set_trace()
    
def generate_keymods():
    
    return 0

# Reference of what bigip.conf cert to fspath looks like
'''
sys file ssl-cert /Common/zyross.some.domain.com {
    cache-path /config/filestore/files_d/Common_d/certificate_d/:Common:zyross.some.domain.com_131415_3
    revision 3
}
'''

'''
:Common:zyross.some.domain.com_131291_1,Modulus=9DF95E1D0552452820BB634A73B54A81675D8F45AC9143D21F95A093629ABE2D9227CF57FF336DE99EFB6E5FD65C557411445AD621B6FDD04498B23ADD85A778BBA356532F786B13726634590A02C66693C2F8DB7DD699EAEC49FB85FFB55CED6102AAF78BBF96224FA7B21C58B26029373B63E2D3AB9FE5AFD68E8D90452F1D9AAEC4E59F8C784CE89EE0CB5F5AA2BE7E7C4B92D4039F7276A27E13F01C83CAE131F44BE29B267E7B9D5309906BEBC5C4B9CB5FA171E1079E50649854351749E2E5060F1D26E9E68D7EFD36FFEBCBEF8DB965CC4C56122861BB5223D8C6652259C96D11FF71AC53394048AFE3AE89E62810C72E52DBA77307BDC08FA9C191A5
'''

def fs_setup(renewed_certs):
   
    logger = get_logger(__name__)
    logger.setLevel(loglevel)

    modulus_dict = {}
    z = zipfile.ZipFile(renewed_certs, "r")
    try:
        os.stat('/tmp/bulkenroll')
        # If folder exists, remove all files from it
        if os.path.isdir('/tmp/bulkenroll') and os.listdir('/tmp/bulkenroll'):
            logger.log(logging.DEBUG, "Removing previous directory /tmp/bulkenroll")
            rm = subprocess.Popen(['rm', '-r', '/tmp/bulkenroll/'],shell=False, stdout=subprocess.DEVNULL)
            if rm.wait() == 0:
                logger.log(logging.INFO, str(f"Extracting {renewed_certs} to /tmp/bulkenroll"))
                p = subprocess.Popen(['unzip', '-d', '/tmp/bulkenroll', renewed_certs],shell=False, stdout=subprocess.DEVNULL)
        elif os.path.isdir('/tmp/bulkenroll') and not os.listdir('/tmp/bulkenroll'):
            logger.log(logging.DEBUG, "Removing previous directory /tmp/bulkenroll")
            rmdir = subprocess.Popen(['rmdir', '/tmp/bulkenroll/'],shell=False, stdout=subprocess.DEVNULL)
            if rmdir.wait() == 0:
                logger.log(logging.INFO, str(f"Extracting {renewed_certs} to /tmp/bulkenroll"))
                p = subprocess.Popen(['unzip', '-d', '/tmp/bulkenroll', renewed_certs],shell=False, stdout=subprocess.DEVNULL)
    except FileNotFoundError as e:
        os.mkdir('/tmp/bulkenroll')
        logger.log(logging.INFO, str(f"Extracting {renewed_certs} to /tmp/bulkenroll"))
        p = subprocess.Popen(['unzip', '-d', '/tmp/bulkenroll', renewed_certs],shell=False, stdout=subprocess.DEVNULL)
    if p.wait() == 0:
        logger.log(logging.INFO, f"Generating modulus for {len(os.listdir('/tmp/bulkenroll'))} renewed certificates...")
        for r,d,f in os.walk('/tmp/bulkenroll'):
            for filename in f:
                filepath = os.path.join(r,filename)
                #cert = x509.load_pem_x509_certificate(certfile_data, default_backend())
                getmod = subprocess.Popen(['openssl', 'x509', '-in', filepath, '-noout', '-modulus'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if not getmod.wait() == 0:
                    getmod = subprocess.Popen(['openssl', 'x509', '-inform', 'DER', '-in', filepath, '-noout', '-modulus'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if not getmod.wait() == 0:
                    continue
                modulus = getmod.stdout.read().decode().rstrip('\n').replace("Modulus=","")
                modulus_dict[modulus] = filepath
        
        
    return modulus_dict

def get_logger(name):

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logfile = logging.FileHandler('install_renews.log')
        # Always log debug to file whether selected or not
        if args.verbose:
            logfile.setLevel(logging.DEBUG)
        else:
            logfile.setLevel(logging.INFO)
        if args.verbose:
            console.setLevel(logging.DEBUG) 
        else:
            console.setLevel(logging.INFO)
        logger.addHandler(console)
        logger.addHandler(logfile)
        logger.setLevel(logging.DEBUG)
        c_format = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')
        console.setFormatter(c_format)
        logfile.setFormatter(c_format)
    return logger

def main():


    parser = argparse.ArgumentParser()
    parser.add_argument('-z', '--zipfile', help="Specify bulk enroll zip file", required=True)
    parser.add_argument('-v', '--verbose', help="Verbose output", required=False, action="store_true")
    global args
    global loglevel
    args = parser.parse_args()
    if args.verbose:
        logger = get_logger(__name__)
        loglevel = logging.DEBUG
        logger.setLevel(loglevel)
        logger.log(logging.DEBUG, "Debugging enabled.")
    else:
        logger = get_logger(__name__)
        loglevel = logging.INFO
        logger.setLevel(loglevel)
    
    
    renews_modulus_dict = fs_setup(args.zipfile)
    locals_modulus_dict = prep_certmods()
    '''
        Have to create reverse dict here because generating the Locals dict with MODULUS as key misses some certificates as
        there can be multiple certificates with the same modulus. Problem is only one of these certificates is referenced
        in the BigIP conf file. We have to find the certificate that matches the cache-path line so we can find the BigIP
        object name of the certificate
    '''
    rev_locals = {}
    for k,v in locals_modulus_dict.items():
        rev_locals.setdefault(v, set()).add(k)
    # List of sets containing duplicate filepaths
    dup_dict = {}
    dups = {k: v for k,v in rev_locals.items() if k in renews_modulus_dict.keys() and len(v) > 1}
    #pdb.set_trace()
    BIGIP_CONF = open('/config/bigip.conf', 'r').read()
    logger.log(logging.INFO, f"If renewed certificate did not find certificate to import, ensure bigip.conf is up to date with `tmsh save sys config` and try to re-run.")
    for key in dups.keys():
        for dup in dups[key]:
            logger.log(logging.DEBUG, f"Checking dup {dup}")
            certobj_path = locate_by_certmod(BIGIP_CONF, dup)
            if certobj_path:
                logger.log(logging.INFO, f"Would: tmsh install sys crypto cert {certobj_path} from-local-file {renews_modulus_dict[key]}")
                # Deleting modulus from renews so we can do a set of common modulus that we know dont have duplicates
                del renews_modulus_dict[key]
                break
    common_modulus = renews_modulus_dict.keys() & rev_locals.keys()
    for modulus in common_modulus:
        # have to pop() rev_locals value as they're all set objects now. We know these will only be 1 value after checking for dups.
        certpath = rev_locals[modulus].pop()
        certobj_path = locate_by_certmod(BIGIP_CONF, certpath)
        if certobj_path:
            logger.log(logging.INFO, f"Would: tmsh install sys crypto cert {certobj_path} from-local-file {renews_modulus_dict[modulus]}")
        else:
            logger.log(logging.DEBUG, f"No match for {certpath} in /config/bigip.conf. Ensure `tmsh save sys config` was run after certificates were imported and re-run.")
    
    
    
if __name__ == '__main__':
    main()    
