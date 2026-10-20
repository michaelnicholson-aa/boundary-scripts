#!/usr/bin/env python3

from cryptography.hazmat.backends import default_backend
from cryptography import x509
import requests
import logging
import json
import re
import os

def get_token(conn, base_url, username, pw, proxies={}):
    auth_url = base_url + '/shared/authn/login'
    auth_data = {}
    auth_data = {
                 "loginProviderName": "tmos",
                 "username": username,
                 "password": pw
                }
    auth_data_json = json.dumps(auth_data)
    if proxies:
        auth_token = conn.post(auth_url, data=auth_data_json, verify=True, proxies=proxies, timeout=5).json()['token']['token']
    else:
        auth_token = conn.post(auth_url, data=auth_data_json, verify=True, timeout=5).json()['token']['token']
    return auth_token

def session_setup(bigip, username, pw, proxies={}):
    logger = get_logger(__name__)
    #logger = logging.getLogger(__name__)
    #logger.setLevel(logging.DEBUG)
    base_url = 'https://' + bigip + '/mgmt'
    conn = requests.Session()
    conn.headers.update({"Content-Type": "application/json"})
    logger.log(logging.DEBUG, 'Obtaining API authorization token for {} on {}'.format(username, bigip))
    if proxies:
        auth_token = get_token(conn, base_url, username, pw, proxies=proxies)
    else:
        auth_token = get_token(conn, base_url, username, pw)
    conn.headers.update({"X-F5-Auth-Token": auth_token})
    return conn, base_url

def local_node_is_active(conn, base_url, proxies={}):
    #log = logging.getLogger(__name__)
    logger = get_logger(__name__)
    #logger.setLevel(logging.DEBUG)
    active = False
    module_url = base_url + '/tm/cm/failover-status'
    if proxies:
        failover_status = conn.get(module_url, proxies=proxies)
    else:
        failover_status = conn.get(module_url)
    # Local device will always be node 0
    f = failover_status.json()["entries"]["https://localhost/mgmt/tm/cm/failover-status/0"]
    if f["nestedStats"]["entries"]["status"]["description"].lower() == 'active':
        logger.log(logging.DEBUG, "Node is Active member")
        return True
    else:
        logger.log(logging.DEBUG, "Node is not active member")


def create_node(conn, base_url, node, proxies={}):

    module_url = base_url + ('/tm/ltm/node')
    node = node
    #node = {"name": "miketest.some.domain.com", "fqdn": {"tmName": "miketest.some.domain.com", "autopopulate": "enabled"}}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(node), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(node))
    return resp

def delete_node(conn, base_url, node, proxies={}):

    module_url = base_url + str('/tm/ltm/node/~Common~%s' % node)
    if proxies:
        resp = conn.delete(module_url, proxies=proxies)
    else:
        resp = conn.delete(module_url)
    return resp

def get_node(conn, base_url, node, proxies={}):
    
    module_url = base_url + str('/tm/ltm/node/~Common~%s' % node)
    if proxies:
        print(module_url)
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def add_pool_member(conn, base_url, pool, member, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/~Common~%s/members' % pool)
    #member = {"name": "192.168.199.199:80", "description": "miketest"}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(member), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(member))
    return resp

def delete_pool_member(conn, base_url, pool, member, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/~Common~%s/members/%s' % (pool,member))
    member = member
    if proxies:
        resp = conn.delete(module_url, proxies=proxies)
    else:
        resp = conn.delete(module_url)
    return resp

def create_pool(conn, base_url, name, members=[],  proxies={}):

    module_url = base_url + '/tm/ltm/pool'
    pool_name = name
    pool_members = members
    pool = {"name": name, "members": members}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(pool), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(pool))
    return resp

def delete_pool(conn, base_url, name, proxies={}):

    module_url = base_url + '/tm/ltm/pool/%s' % name
    if proxies:
        resp = conn.delete(module_url, proxies=proxies)
    else:
        resp = conn.delete(module_url)
    return resp

def disable_pool_member(conn, base_url, pool, member, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/~Common~%s/members/~Common~%s' % (pool, member))
    member = member
    disable = {"session": "user-disabled"}
    if proxies:
        resp = conn.patch(module_url, data=json.dumps(disable), proxies=proxies)
    else:
        resp = conn.patch(module_url, data=json.dumps(disable))
    return resp

def enable_pool_member(conn, base_url, pool, member, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/~Common~%s/members/~Common~%s' % (pool, member))
    member = member
    enable = {"session": "user-enabled"}
    if proxies:
        resp = conn.patch(module_url, data=json.dumps(enable), proxies=proxies)
    else:
        resp = conn.patch(module_url, data=json.dumps(enable))
    return resp

def cert_is_compliant(certificate, dns_name='', parent_profile=''):


    # lets look at certs!
    reason_string = ''
    compliance_status = True

    cert = x509.load_pem_x509_certificate(str(certificate), default_backend())
    delta = cert.not_valid_after - cert.not_valid_before
    if delta.days > 397:
        compliance_status = False
        reason_string = str("Certificate exceeds 397 day lifetime: %s " % delta)
    # Update this to regex, look for IP addresses too
    new_ip_pat = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')
    non_compliant_strings = ['dev', 'test', '*']
    found_non_compliant_sans = []
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san.value.get_values_for_type(x509.DNSName)
        if len(sans) == 1 and sans[0].lower() == dns_name.lower():
            found_non_compliant_sans = False
        else:
            for name in sans:
                ipcheck = False
                for item in non_compliant_strings:
                    if item in name.lower():
                        logging.debug('Found non-compliant SAN: %s ' % name)
                        found_non_compliant_sans.append(name)
                        break
                ipcheck = re.match(new_ip_pat, name)
                if ipcheck:
                    logging.debug('Found non-compliant SAN: %s ' % name)
                    found_non_compliant_sans.append(name)
    except x509.extensions.ExtensionNotFound:
        # Don't fail the check just because there are no SANs
        pass
    if found_non_compliant_sans:
        if reason_string:
            reason_string += str(" | Found Non-Compliant SAN(s): ")
            for san in found_non_compliant_sans:
                reason_string += str("%s " % san)
            compliance_status = False
        else:
            reason_string += str("Found Non-Compliant SAN(s): ")
            for san in found_non_compliant_sans:
                reason_string += str("%s " % san)
            compliance_status = False
    if parent_profile.lower() != 'clientssl_sec-baseline':
        compliance_status = False
        if reason_string:
            reason_string += str(" | Parent profile is not set to clientssl_sec-baseline: %s" % parent_profile)
        else:
            reason_string = str("Parent profile is not set to clientssl_sec-baseline: %s" % parent_profile)

    return compliance_status, reason_string


def replace_pool_members(conn, base_url, pool, newmembers, proxies={}):

    # FQDN members must already be nodes

    module_url = base_url + ('/tm/ltm/pool/~Common~%s' % pool)
    if proxies:
        resp = conn.patch(module_url, data=json.dumps(newmembers), proxies=proxies)
    else:
        resp = conn.patch(module_url, data=json.dumps(newmembers))
    return resp

def get_all_pools(conn, base_url, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/')
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def get_all_pools_full(conn, base_url, proxies={}):

    module_url = base_url + ('/tm/ltm/pool?expandSubcollections=true')
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def get_all_nodes(conn, base_url, proxies={}):

    module_url = base_url + ('/tm/ltm/node/')
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def get_pool_members(conn, base_url, pool, proxies={}):

    module_url = base_url + ('/tm/ltm/pool/~Common~%s/members' % pool)
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    if resp.ok:
        members = []
        j_resp = resp.json()
        for member in j_resp['items']:
            d = {}
            d["name"] = member["name"]
            d["address"] = member["address"]
            members.append(d)
    return members

def install_cert(conn, base_url, name, proxies={}):

    #name = str(name + '.crt')
    # Get name from calling func and look for it in /shared/tmp
    cert_file = os.path.join("/shared/tmp", name)
    module_url = base_url + ('/tm/sys/crypto/cert')
    payload = {"command": "install", "name": name, "from-local-file": cert_file}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def install_key(conn, base_url, name, proxies={}):

    #name = str(name + '.key')
    # Get name from calling func and look for it in /shared/tmp
    key_file = os.path.join("/shared/tmp", name)
    module_url = base_url + ('/tm/sys/crypto/key')
    payload = {"command": "install", "name": name, "from-local-file": key_file}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def create_ssl_profile(conn, base_url, cert='miketest.crt', key='miketest.key', name="placeholder.sslpro",  proxies={}):

    #profile_name = str(name + '.sslpro')
    # Get name from calling func
    module_url = base_url + ('/tm/ltm/profile/client-ssl')
    #cert = name + '.crt'
    #key = name + '.key'
    payload = {"name": name, "cert": cert, "key": key, "defaultsFrom": "clientssl_sec-baseline"}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def modify_ssl_profile(conn, base_url, name, properties, proxies={}):

    profile_name = str(name.split('.')[0] + '.sslpro')
    module_url = base_url + ('/tm/ltm/profile/client-ssl/%s' % profile_name)
    payload = properties
    if proxies:
        resp = conn.patch(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.patch(module_url, data=json.dumps(payload))
    return resp

def delete_ssl_profile(conn, base_url, name, proxies={}):

    profile_name = str(name.split('.')[0] + '.sslpro')
    module_url = base_url + ('/tm/ltm/profile/client-ssl/%s' % profile_name)
    if proxies:
        resp = conn.delete(module_url, proxies=proxies)
    else:
        resp = conn.delete(module_url)
    return resp

def create_vip(conn, base_url, payload, proxies={}):

    module_url = base_url + ('/tm/ltm/virtual')
    payload = payload
    #payload = {"name": "miketest.vs", "destination": "192.168.237.237:443", "ipProtocol": "tcp", "port": "443", "mask": "255.255.255.255",
               #"pool": "miketest.pool", "source": "0.0.0.0/0"}

    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def get_vips(conn, base_url, vip='', proxies={}):

    if vip:
        module_url = base_url + str('/tm/ltm/virtual/%s?expandSubcollections=true' % vip)
    else:
        module_url = base_url + '/tm/ltm/virtual/?expandSubcollections=true'
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def get_vips_by_profile(vips_list, profile):


    for vip in vips_list:
        for item in vip['profilesReference']['items']:
            if profile in item['fullPath'].lower():
                print('VIRTUAL SERVER:\t\t%s\nDESTINATION ADDRESS:\t%s\nPROFILE:\t\t%s\n\n' % (vip['fullPath'], vip['destination'], item['fullPath']))


    '''
     Supply this function with a list of VS dictionairies
     Normal BigIP Response is stuctured as:
         response{"items": [{vip1}, {vip2}, {vip3}]}

     We're just going to supply the list by returning response['items']
     VIPs have base attributes e.g. vip1['destination'] or vip1['vsIndex']
     When expandSubcollections is true, can dive into attached profiles and policies
     e.g. vip1['profilesReference': {"isSubcollection": "true", "items": [{profile1}, {profile2}]
     e.g. vip1['policiesReference': {"isSubcollcetion": "true", "items": [{policy1}, {policy2}]
    '''
    exit()

def get_profile(conn, base_url, profile, proxies={}):


    module_url = str(base_url + '/tm/ltm/profile/client-ssl/%s' % (profile))
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

    '''
    {u'alertTimeout': u'60',
 u'allowDynamicRecordSizing': u'disabled',
 u'allowExpiredCrl': u'disabled',
 u'allowNonSsl': u'disabled',
 u'appService': u'none',
 u'authenticate': u'once',
 u'authenticateDepth': 9,
 u'bypassOnClientCertFail': u'disabled',
 u'bypassOnHandshakeAlert': u'disabled',
 u'c3dDropUnknownOcspStatus': u'drop',
 u'c3dOcsp': u'none',
 u'caFile': u'/Common/DOD_Roots_Email_ID_ECA.crt',
 u'caFileReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~DOD_Roots_Email_ID_ECA.crt?ver=14.1.4.6'},
 u'cacheSize': 262144,
 u'cacheTimeout': 3600,
 u'cert': u'/Common/nhdsm.some.domain.com.crt',
 u'certExtensionIncludes': [u'basic-constraints', u'subject-alternative-name'],
 u'certKeyChain': [{u'appService': u'none',
                    u'cert': u'/Common/nhdsm.some.domain.com.crt',
                    u'certReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~nhdsm.some.domain.com.crt?ver=14.1.4.6'},
                    u'chain': u'none',
                    u'key': u'/Common/nhdsm.some.domain.com.key',
                    u'keyReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-key/~Common~nhdsm.some.domain.com.key?ver=14.1.4.6'},
                    u'name': u'nhdsm.some.domain.com_0',
                    u'passphrase': u'****',
                    u'usage': u'SERVER'}],
 u'certLifespan': 30,
 u'certLookupByIpaddrPort': u'disabled',
 u'certReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~nhdsm.some.domain.com.crt?ver=14.1.4.6'},
 u'chain': u'none',
 u'cipherGroup': u'/Common/f5-secure',
 u'cipherGroupReference': {u'link': u'https://localhost/mgmt/tm/ltm/cipher/group/~Common~f5-secure?ver=14.1.4.6'},
 u'ciphers': u'none',
 u'clientCertCa': u'/Common/DOD_Roots_Email_ID_ECA.crt',
 u'clientCertCaReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~DOD_Roots_Email_ID_ECA.crt?ver=14.1.4.6'},
 u'crlFile': u'none',
 u'defaultsFrom': u'/Common/clientssl',
 u'defaultsFromReference': {u'link': u'https://localhost/mgmt/tm/ltm/profile/client-ssl/~Common~clientssl?ver=14.1.4.6'},
 u'description': u'none',
 u'destinationIpBlacklist': u'none',
 u'destinationIpWhitelist': u'none',
 u'destinationIpWhitelist': u'none',
 u'forwardProxyBypassDefaultAction': u'intercept',
 u'fullPath': u'nhdsm.sslpro',
 u'generation': 1,
 u'genericAlert': u'enabled',
 u'handshakeTimeout': u'60',
 u'hostnameBlacklist': u'none',
 u'hostnameWhitelist': u'none',
 u'inheritCaCertkeychain': u'true',
 u'inheritCertkeychain': u'false',
 u'key': u'/Common/nhdsm.some.domain.com.key',
 u'keyReference': {u'link': u'https://localhost/mgmt/tm/sys/file/ssl-key/~Common~nhdsm.some.domain.com.key?ver=14.1.4.6'},
 u'kind': u'tm:ltm:profile:client-ssl:client-sslstate',
 u'maxActiveHandshakes': u'indefinite',
 u'maxAggregateRenegotiationPerMinute': u'indefinite',
 u'maxRenegotiationsPerMinute': 5,
 u'maximumRecordSize': 16384,
 u'modSslMethods': u'enabled',
 u'mode': u'enabled',
 u'name': u'nhdsm.sslpro',
 u'notifyCertStatusToVirtualServer': u'disabled',
 u'ocspStapling': u'disabled',
 u'passphrase': u'****',
 u'peerCertMode': u'ignore',
 u'peerNoRenegotiateTimeout': u'10',
 u'proxyCaCert': u'none',
 u'proxyCaKey': u'none',
 u'proxyCaPassphrase': u'****',
 u'proxySsl': u'disabled',
 u'proxySslPassthrough': u'disabled',
 u'renegotiateMaxRecordDelay': u'10',
 u'renegotiatePeriod': u'indefinite',
 u'renegotiateSize': u'indefinite',
 u'renegotiation': u'enabled',
 u'retainCertificate': u'true',
 u'secureRenegotiation': u'require',
 u'selfLink': u'https://localhost/mgmt/tm/ltm/profile/client-ssl/nhdsm.sslpro?ver=14.1.4.6',
 u'serverName': u'none',
 u'sessionMirroring': u'disabled',
 u'sessionTicket': u'disabled',
 u'sessionTicketTimeout': 0,
 u'sniDefault': u'false',
 u'sniRequire': u'false',
 u'sourceIpBlacklist': u'none',
 u'sourceIpWhitelist': u'none',
 u'sslC3d': u'disabled',
 u'sslForwardProxy': u'disabled',
 u'sslForwardProxyBypass': u'disabled',
 u'sslForwardProxyVerifiedHandshake': u'disabled',
 u'sslSignHash': u'any',
 u'strictResume': u'disabled',
 u'tmOptions': u'{ dont-insert-empty-fragments no-ssl no-tlsv1.1 no-tlsv1 }',
 u'uncleanShutdown': u'enabled'}
'''

def get_cert(conn, base_url, cert, proxies={}):

    # Going to bake-in hidden options. Why would we not want this?
    module_url = base_url + str('/tm/sys/file/ssl-cert/~Common~%s?options=-hidden' % cert)
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp
    

    # Reference
    '''
{u'bundleCertificatesReference': {u'isSubcollection': True,
                                  u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~alm.some.domain.com.crt/bundle-certificates?ver=14.1.4.6'},
 u'certValidatorsReference': {u'isSubcollection': True,
                              u'link': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~alm.some.domain.com.crt/cert-validators?ver=14.1.4.6'},
 u'certificateKeyCurveName': u'none',
 u'certificateKeySize': 2048,
 u'checksum': u'SHA1:1692:4c58b39ba0718f8ce7973fc9424d18ed50b6e32f',
 u'createTime': u'2021-02-05T13:46:20Z',
 u'createdBy': u'root',
 u'expirationDate': 1707057366,
 u'expirationString': u'Feb  4 14:36:06 2024 GMT',
 u'fingerprint': u'SHA256/D8:EB:CD:C8:67:CA:A5:8C:07:55:92:54:75:65:1A:00:18:D7:06:EC:76:EB:E3:69:FF:96:20:C7:2C:51:E2:BB',
 u'fullPath': u'/Common/alm.some.domain.com.crt',
 u'generation': 1,
 u'isBundle': u'false',
 u'issuer': u'CN=DOD SW CA-60,OU=PKI,OU=DoD,O=U.S. Government,C=US',
 u'keyType': u'rsa-public',
 u'kind': u'tm:sys:file:ssl-cert:ssl-certstate',
 u'lastUpdateTime': u'2021-02-05T13:46:20Z',
 u'mode': 33188,
 u'name': u'alm.some.domain.com.crt',
 u'partition': u'Common',
 u'revision': 2,
 u'selfLink': u'https://localhost/mgmt/tm/sys/file/ssl-cert/~Common~alm.some.domain.com.crt?ver=14.1.4.6',
 u'serialNumber': u'35260',
 u'size': 1692,
 u'subject': u'CN=alm.some.domain.com,OU=USN,OU=PKI,OU=DoD,O=U.S. Government,C=US',
 u'subjectAlternativeName': u'DNS:alm.some.domain.com',
 u'updatedBy': u'root',
 u'version': 3}
    '''

#def get_certfile(

def get_referenced_link(conn, bigip, reference_link, options='', proxies={}):
   
    vers_pat = re.compile(r"ver=(\d+\.\d+\.\d+)(\.\d+)?")

    if options:
        reference_link = reference_link.replace('localhost', bigip)
        reference_link = re.sub(vers_pat, str('options=%s' % (options)) , reference_link)
        #reference_link = reference_link.replace('?ver=14.1.4.6', str('?options=%s' % (options)))
        print(reference_link)
    else:
        reference_link = reference_link.replace('localhost', bigip)
    if proxies:
        resp = conn.get(reference_link, proxies=proxies)
    else:
        resp = conn.get(reference_link)
    return resp

def get_certfile(conn, base_url, cache_path, proxies={}):

    module_url = base_url + '/tm/util/bash'
    payload = {"command":"run", "utilCmdArgs": str("-c \'cat %s\'" % (cache_path))}
    asdf = json.dumps(payload)
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def get_keymodsfile(conn, base_url, filepath='/shared/tmp/keymods.txt', proxies={}):
    # Hard baking filepath for now. If we let anyone populate this filename they can see any file with root privs.
    filepath = '/shared/tmp/keymods.txt'
    module_url = base_url + '/tm/util/bash'
    payload = {"command":"run", "utilCmdArgs": str("-c \'cat %s\'" % (filepath))}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def remove_crt_key(conn, base_url, name, proxies={}):
    base_folder = "/shared/tmp"
    fullpath = str(f"{base_folder}/{name}")
    module_url = str(base_url + '/tm/util/bash')
    payload = {"command":"run", "utilCmdArgs": str(f"-c \'rm {fullpath}\'")}
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), proxies=proxies)
    else:
        resp = conn.post(module_url, data=json.dumps(payload))
    return resp

def upload_file(conn, base_url, dest_path="/shared/file-transfer/uploads/", filename="placeholder.txt", proxies={}):

    # Plagiarized from https://github.com/leonardobdes/BIGREST/blob/c416fa52ec95295a57a1e5331e3e6958ac71d4c3/bigrest/big.py#L403
    logger = get_logger(__name__)
    #logger.setLevel(logging.DEBUG)
    if not os.path.exists(filename):
        logger.log(logging.CRITICAL, "Unable to locate %s" % filename)
    filename_without_path = os.path.basename(filename)
    # Normalize URI (remove trailing /)
    if dest_path.endswith('/'):
        dest_path = dest_path[:-1]
    module_url = base_url + dest_path + '/' + filename_without_path
    # Start setting up bytes/data transfer
    conn.headers.update({"Content-Type": "application/octet-stream"})
    REST_API_MAXIMUM_CHUNK_SIZE = 10489576
    range_start = 0
    range_size = REST_API_MAXIMUM_CHUNK_SIZE - 1
    range_end = range_size
    size = os.stat(filename).st_size - 1
    with open(filename, "rb") as file_:
        if size <= range_size:
            # Chunk size is large enough to transfer whole/rest of file
            conn.headers.update({"Content-Range": "{}-{}/{}".format(range_start,size,(size + 1))})
            logger.log(logging.DEBUG, "{}-{}/{}".format(range_start,size,(size+1)))
            if proxies:
                resp = conn.post(module_url, data=file_.read(size + 1), timeout=10, proxies=proxies)
            else:
                 resp = conn.post(module_url, data=file_.read(size + 1), timeout=10)
            if resp.status_code != 200:
                logger.log(logging.CRITICAL, "File %s failed to upload to %s" % (filename_without_path, module_url))
                logger.log(logging.DEBUG, resp.content)
                conn.headers.pop("Content-Range")
                conn.headers.update({"Content-Type": "application/json"})
                exit(1)
        else:
            while size >= range_start:
                if range_end > size:
                    range_end = size
                content_range = "{}-{}/{}".format(range_start,range_end,(size + 1))
                logger.log(logging.DEBUG, content_range)
                conn.headers.update({"Content-Range": content_range})
                bytes_to_read = (range_end - range_start) + 1
                if proxies:
                    resp = conn.post(module_url, data=file_.read(size + 1), timeout=10, proxies=proxies)
                else:
                    resp = conn.post(module_url, data=file_.read(bytes_to_read), timeout=10)
                if resp.status_code !=200:
                    logger.log(logging.CRITICAL, "File %s failed to upload to %s" % (filename_without_path, module_url))
                    logger.log(logging.DEBUG, resp.content)
                    conn.headers.pop("Content-Range")
                    conn.headers.update({"Content-Type": "application/json"})
                    exit(1)
                range_start = range_end + 1
                range_end = range_end + range_size + 1
    conn.headers.pop("Content-Range")
    conn.headers.update({"Content-Type": "application/json"})

    return resp

def move_file(conn, base_url, filename, src_path="/var/config/rest/downloads/", dst_path="/shared/tmp/", proxies={}):

    logger = get_logger(__name__)
    #logger.setLevel(logging.DEBUG)
    module_url = base_url + '/tm/util/unix-mv'
    src_file = src_path + filename
    dst_file = dst_path + filename
    payload = {"command":"run", "utilCmdArgs": str(src_file + " " + dst_file)}
    logger.log(logging.INFO, "Moving %s to %s" % (src_file, dst_file))
    logger.log(logging.DEBUG, payload)
    logger.log(logging.DEBUG, module_url)
    if proxies:
        resp = conn.post(module_url, data=json.dumps(payload), timeout=10, proxies=proxies)
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to move %s to %s" % (src_file, dst_file))
            logger.log(logging.DEBUG, resp.content)
    else:
        resp = conn.post(module_url, data=json.dumps(payload), timeout=10)
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to move %s to %s" % (src_file, dst_file))
            logger.log(logging.DEBUG, resp.content)
    return resp

def add_profiles(conn, base_url, virtual_server="miketest.vs", profiles=[], proxies={}):
    
    # Expecting list of profile names (e.g. "http", "tcp", "fasL4")
    logger = get_logger(__name__)
    #logger.setLevel(logging.DEBUG)
    virtual_server = str('~Common~' + virtual_server)
    module_url = base_url + '/tm/ltm/virtual/' + virtual_server 
    # Changing names to k,v pairs for JSON dumps
    payload_profiles = []
    for profile in profiles:
        #profiles.remove(profile)    
        payload_profiles.append({"name": profile})
    payload = {"profiles": payload_profiles}
    logger.log(logging.INFO, "Adding %s to %s" % (profiles, virtual_server))
    logger.log(logging.DEBUG, json.dumps(payload))
    # Need to wrap profiles into dict (JSON Object (not array) required)
    if proxies:
        # Must be PATCH method
        resp = conn.patch(module_url, data=json.dumps(payload), proxies=proxies)
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to update profiles on %s" % virtual_server)
            logger.log(logging.DEBUG, resp.content)
    else:
        # Must be PATCH method
        resp = conn.patch(module_url, data=json.dumps(payload))
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to update profiles on %s" % virtual_server)
            logger.log(logging.DEBUG, resp.content)

    return resp

def add_rules(conn, base_url, virtual_server="miketest.vs", rules=[], proxies={}):

    # Expecting list of profile names (e.g. "http", "tcp", "fasL4")
    logger = get_logger(__name__)
    #logger.setLevel(logging.DEBUG)
    virtual_server = str('~Common~' + virtual_server)
    module_url = base_url + '/tm/ltm/virtual/' + virtual_server
    # Changing names to k,v pairs for JSON dumps
    payload_rules = []
    for rule in rules:
        payload_rules.append(str("/Common/" + rule))
    payload = {"rules": payload_rules}
    logger.log(logging.INFO, "Adding %s to %s" % (payload_rules, virtual_server))
    logger.log(logging.DEBUG, json.dumps(payload))
    # Need to wrap rules into dict (JSON Object (not array) required)
    if proxies:
        # Must be PATCH method
        resp = conn.patch(module_url, data=json.dumps(payload), proxies=proxies)
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to update rules on %s" % virtual_server)
            logger.log(logging.DEBUG, resp.content)
    else:
        # Must be PATCH method
        resp = conn.patch(module_url, data=json.dumps(payload))
        if resp.status_code !=200:
            logger.log(logging.CRITICAL, "Failed to update rules on %s" % virtual_server)
            logger.log(logging.DEBUG, resp.content)

    return resp



def check_whitelist_compliance(vips_list):

    '''
    To check for whitelist compliance:

    1) ClientSSL profile must use a certificate that:
       a) Has 397 days of lifetime or shorter
       b) Does not have any DNS SAN that contains 'dev', 'test', 'preprod', 'pre-prod', etc.

       ACTION: For each VIP: query the client ssl profile and add it to the compliance dictionary if it is unique.
               Add a lightweight dict for each vip that contains the name, profile, and compliance status
               After checking every VIP, check if each ssl profile is whitelist compliant
               If the ssl profile is compliant, return to each VIP and change its compliance if the associated profile
               has been marked compliant.
               Report results

    '''

    compliance_dict = {}
    compliance_dict['vips'] = []
    compliance_dict['profiles'] = []

   # For any VIPS that have client ssl profiles, associate the profile with a vip and add it to a profiles list
   # Inspect each ssl profile to find the certificate used
   # Check the certificate for 397 lifetime and SAN violations

    for vip in vips_list:
        sslvip = {}
        for item in vip['profilesReference']['items']:
            if item['context'] == 'clientside':
                compliance_dict['profiles'].append({"name": item['name'], "cert": ''})
                sslvip['name'] = vip['name']
                sslvip['profiles'] = []
                sslvip['profiles'].append(item['name']) # Done this way in case a VIP has more than one clientsslprofile
                compliance_dict['vips'].append(sslvip)
    # Checked all VIPS for client ssl profiles
    # Need to check get certificate data for every client ssl profile used
    for profile in compliance_dict['profiles']:
        prof = json.loads(get_profile(conn, base_url, profile['name']).content)
        cert = json.loads(get_referenced_link(conn, bigip, resp['certReference']['link'], '-hidden').content)
        cert_path = cert['cachePath']
        certfile = json.loads(get_certfile(conn, base_url, cert_path).content)
        compliance_dict['profiles'][profile][cert] = certfile

def create_csr(conn, base_url, certname, keyname, cert_cn, cert_org, cert_country, san_string, proxies={}):
    module_url = base_url + str('/tm/sys/crypto/csr')
    payload = {}
    if not '.crt' in certname and not '.cer' in certname:
        payload['name'] = certname + '.csr'
    else:
        certname = certname.replace('.cer', '')
        certname = certname.replace('.crt', '')
        payload['name'] = certname + '.csr'
    payload['common-name'] = cert_cn
    payload['organization'] = cert_org
    payload['country'] = cert_country
    payload['key'] = keyname
    payload['subjectAlternativeNames'] = san_string
    payload = json.dumps(payload)
    if proxies:
        resp = conn.post(module_url, data=payload, proxies=proxies)
    else:
        resp = conn.post(module_url, data=payload)
    return resp

def get_address_lists(conn, base_url, proxies={}):
    module_url = base_url + str('/tm/security/firewall/address-list')
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp

def get_irule(conn, base_url, rule, proxies={}):
    if '/' in rule:
        rule = rule.replace('/', '~')
    module_url = base_url + str('/tm/ltm/rule/%s' % rule)
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp
    
def get_pool(conn, base_url, pool, proxies={}):
    if '/' in pool:
        pool = pool.replace('/', '~')
    module_url = base_url + str('/tm/ltm/pool/%s?expandSubcollections=true' % pool)
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp


def get_key(conn, base_url, keyname, proxies={}):
    module_url = base_url + str('/tm/sys/crypto/key/%s' % keyname)    
    if proxies:
        resp = conn.get(module_url, proxies=proxies)
    else:
        resp = conn.get(module_url)
    return resp
  
    

def get_logger(name):

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logger.addHandler(console)
        c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        console.setFormatter(c_format)
    return logger

if __name__ == '__main__':
    print('okay')
    exit(0)





