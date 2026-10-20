#!/usr/bin/env python3

from mike_f5 import *
import subprocess
import ipaddress
import argparse
import requests
import getpass
import logging
import pprint
import json
import sys
import pdb
import os

#Global vars
username = "removed"
#proxies = {"http": "http://proxy.some.domain.com:8080", "https": "http://proxy.some.domain.com:8443"}
proxies = {}
systems = {'cloud': {'east': {'inner': ({'ip': '192.168.201.19',
                               'name': 'peibip1.some.domain.com'},
                              {'ip': '192.168.201.20',
                               'name': 'peibip2.some.domain.com'}),
                    'outer': ({'ip': '192.168.201.11',
                               'name': 'peobip1.some.domain.com'},
                              {'ip': '192.168.201.12',
                               'name': 'peobip2.some.domain.com'})},
           'west': {'inner': ({'ip': '192.168.200.19',
                               'name': 'pwibip1.some.domain.com'},
                              {'ip': '192.168.200.20',
                               'name': 'pwibip2.some.domain.com'}),
                    'outer': ({'ip': '192.168.200.11',
                               'name': 'pwobip1.some.domain.com'},
                              {'ip': '192.168.200.12',
                               'name': 'pwobip2.some.domain.com'})}},
 'core': ({'ip': '192.168.47.109', 'name': 'ps2216.some.domain.com'},
          {'ip': '192.168.47.111', 'name': 'ps2217.some.domain.com'}),
 'edmz': {'inner': ({'ip': '192.168.22.145',
                     'name': 'ss3470.some.domain.com'},
                    {'ip': '192.168.22.146', 'name': 'ss3471.some.domain.com'}),
          'outer': ({'ip': '192.168.22.30', 'name': 'ss2954.some.domain.com'},
                    {'ip': '192.168.22.32', 'name': 'ss2955.some.domain.com'})}}


def main():

    # Set up argparser
    parser = argparse.ArgumentParser(description="A tool to help simplify passthrough and break-and-inspect PDSS builds. May plan to add more functionality in the future.\nPlease remember to update AFM rules yourself.") 
    parser.add_argument("-b", "--buildfile", help="Specify buildfile", required=True)
    parser.add_argument("-v", "--verbose", help="Enables verbose logging - very chatty!", action="store_true")
    break_and_inspect = parser.add_argument_group('break_and_inspect')
    break_and_inspect.add_argument("-c", "--certfile", help="Certificate to be used for client-ssl profile", required=False)
    break_and_inspect.add_argument("-k", "--keyfile", help="Key to be used for client-ssl profile", required=False)
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

    # Check buildfile exists
    build_file = args.buildfile
    if not os.path.exists(build_file): 
        logger.log(logging.CRITICAL, "Fatal Error! - Problem locating build file %s" % build_file)
        exit(1)

    if args.certfile and args.keyfile:
        # If these were provided as arguments but don't check out, don't even start the build.
        # After reading in file below, if build_type is breakandinspect and these weren't provided exit out.
        crt_mod = subprocess.Popen(['openssl', 'x509', '-modulus', '-in', args.certfile, '-noout'], shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        key_mod = subprocess.Popen(['openssl', 'rsa', '-modulus', '-in', args.keyfile, '-noout'], shell=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        crt_mod_out = crt_mod.stdout.read()
        key_mod_out = key_mod.stdout.read()
        if not crt_mod_out == key_mod_out or not crt_mod_out or not key_mod_out:
            logger.log(logging.CRITICAL, "Fatal Error! - CRT/KEY MODULUS MISMATCH:\n\n%s\n%s\n\n%s\n%s" % (args.certfile, crt_mod_out, args.keyfile, key_mod_out))
            exit(1)

    # Open buildfile, read data into 'j'
    with open(build_file, 'r') as INFO_FILE:
        f = INFO_FILE.read()

    j = json.loads(f)

    build_type = j['build_type']
    build_name = j['build_name']
    if j['snap_ticket'] == '':
        snap_ticket = "SNAP Ticket: Not provided"
    else:
        snap_ticket = str("SNAP Ticket: " + j['snap_ticket'])
    west_inner_vs_ip = j['region']['west']['inner']['ip']
    west_inner_vs_port = j['region']['west']['inner']['port']
    west_outer_vs_ip = j['region']['west']['outer']['ip']
    west_outer_vs_port = j['region']['west']['outer']['port']
    east_inner_vs_ip = j['region']['east']['inner']['ip']
    east_inner_vs_port = j['region']['east']['inner']['port']
    east_outer_vs_ip = j['region']['east']['outer']['ip']
    east_outer_vs_port = j['region']['east']['outer']['port']
    common_inner_pool_members = j['common']['inner_pool_members']
    try:
        client_ssl_override = j['client_ssl_override']
    except KeyError as e:
        client_ssl_override = ""
        pass
    

    if build_type == "breakandinspect" and (not args.certfile or not args.keyfile):
        logger.log(logging.CRITICAL, "Build type is break and inspect but cannot load cert/keys!")
        if not args.certfile:
            logger.log(logging.CRITICAL, "Certificate not found or certificate not specified")
        if not args.keyfile:
            logger.log(logging.CRITICAL, "Key not found or key not specified")
        exit(1)

    #common_inner_pool_node = (common_inner_pool_node_addr,common_inner_pool_node_port)

    # Ensuring loaded values are present but not necessarily if they are valid.
    check_east_vars = {"build_type": build_type, "build_name": build_name, "east_inner_vs_ip": east_inner_vs_ip, "east_inner_vs_port": east_inner_vs_port, 
                       "east_outer_vs_ip": east_outer_vs_ip, "east_outer_vs_port": east_outer_vs_port, "common_inner_pool_members": common_inner_pool_members}
    check_west_vars = {"build_type": build_type, "build_name": build_name, "west_inner_vs_ip": west_inner_vs_ip, "west_inner_vs_port": west_inner_vs_port, 
                       "west_outer_vs_ip": west_outer_vs_ip, "west_outer_vs_port": west_outer_vs_port, "common_inner_pool_members": common_inner_pool_members}
    # Build East
    try:
        assert(build_type)
        assert(build_name)
        assert(east_inner_vs_ip)
        assert(east_inner_vs_port)
        assert(east_outer_vs_ip)
        assert(east_outer_vs_port)
        assert(common_inner_pool_members)
    except AssertionError as e:
        logger.log(logging.CRITICAL, "Missing a needed variable!")
        exit(1)
    print("\n")
    pprint.pprint(check_east_vars)
    print("\n")
    pprint.pprint(check_west_vars)
    print("\n")
    # Add-DnsServerResourceRecordA -name videohosttemp -zonename some.domain.com -computername cloudhost1.some.domain.com -allowupdateany -ipv4address 192.168.208.238 -TimetoLive 00:05:00;
    dns_basename = str(build_name.split('.')[0])
    dns_basedot = str('.'.join(build_name.split('.')[1:]))
    east_cloud_dns = str("Add-DnsServerResourceRecordA -name %s -zonename %s -computername cloudhost1.some.domain.com -allowupdateany -ipv4address %s -TimetoLive 00:05:00;"
                         % (dns_basename, dns_basedot, east_outer_vs_ip))
    east_core_dns = str(east_cloud_dns.replace("cloudhost1.some.domain.com", "pxdc10.apps.someother.domain.com")) 
    west_cloud_dns = str("Add-DnsServerResourceRecordA -name %s -zonename %s -computername cloudhost1.some.domain.com -allowupdateany -ipv4address %s -TimetoLive 00:05:00;"
                         % (dns_basename, dns_basedot, west_outer_vs_ip))
    west_core_dns = str(west_cloud_dns.replace("cloudhost1.some.domain.com", "pxdc10.apps.someother.domain.com")) 
    print(east_cloud_dns)
    print("\n")
    print(east_core_dns)
    print("\n")
    print(west_cloud_dns)
    print("\n")
    print(west_core_dns)
    print("\n")

    ## Add-DnsServerResourceRecordA -name videohosttemp -zonename some.domain.com -computername cloudhost1.some.domain.com -allowupdateany -ipv4address 192.168.208.238 -TimetoLive 00:05:00;
    #dns_basename = str(build_name.split('.'))
    #dns_basedot = str('.'.join(build_name.split('.')[1:]))
    #west_cloud_dns = str("Add-DnsServerResourceRecordA -name %s -zonename %s -computername cloudhost1.some.domain.com -allowupdateany -ipv4address %s -TimetoLive 00:05:00;"
    #                     % (dns_basename, dns_basedot, west_outer_vs_ip))
    #west_core_dns = str(west_cloud_dns.replace("cloudhost1.some.domain.com", "pxdc10.apps.someother.domain.com"))
#
    confirm = input("Proceed with build? [y/n]: ")

    if confirm.strip().lower() != "y" and confirm.strip().lower() != "yes":
        exit(1)

    # Making PW global here so we don't get prompted twice both build_region calls or before validation/confirmation steps are done.
    global pw
    pw = getpass.getpass("Cloud PW: ")
    build_region('east', build_type, build_name, east_inner_vs_ip, east_inner_vs_port, 
                 east_outer_vs_ip, east_outer_vs_port, common_inner_pool_members, args.certfile, args.keyfile, snap_ticket, client_ssl_override, loglevel)
    
    # Build West
    try:
        assert(build_type)
        assert(build_name)
        assert(west_inner_vs_ip)
        assert(west_inner_vs_port)
        assert(west_outer_vs_ip)
        assert(west_outer_vs_port)
    except BaseException as e:
        logger.log(logging.CRITICAL, "Missing a needed variable!")
        exit(1)
    build_region('west', build_type, build_name, west_inner_vs_ip, west_inner_vs_port, 
                 west_outer_vs_ip, west_outer_vs_port, common_inner_pool_members, args.certfile, args.keyfile, snap_ticket, client_ssl_override, loglevel)

    # Add-DnsServerResourceRecordA -name videohosttemp -zonename some.domain.com -computername cloudhost1.some.domain.com -allowupdateany -ipv4address 192.168.208.238 -TimetoLive 00:05:00;
    dns_basename = str(build_name.split('.'))
    dns_basedot = dns_basename + "."
    west_cloud_dns = str("Add-DnsServerResourceRecordA -name %s -zonename %s -computername cloudhost1.some.domain.com -allowupdateany -ipv4address %s -TimetoLive 00:05:00;"
                         % (dns_basename, build_name.replace(dns_basedot, ""), east_outer_vs_ip))
    west_core_dns = str(west_cloud_dns.replace("cloudhost1.some.domain.com", "pxdc10.apps.someother.domain.com"))

def build_region(region, build_type, build_name, inner_vs_ip, inner_vs_port, outer_vs_ip, outer_vs_port, 
                 inner_pool_members, certfile, keyfile, snap_ticket, client_ssl_override, loglevel):

    logger = get_logger(__name__)
    logger.setLevel(loglevel)

    inner_active_found = False
    for system in systems['cloud'][region]['inner']:
        bigip = system["name"]
        logger.log(logging.INFO, "Checking %s for active node..." % bigip)          
        try:
            #conn, base_url = session_setup(bigip, username, pw, proxies=proxies)
            conn, base_url = session_setup(bigip, username, pw)
            #if local_node_is_active(conn, base_url, proxies=proxies):
            if not local_node_is_active(conn, base_url):
                continue
            else:
                logger.log(logging.INFO, "%s is active node - proceeding with build..." % bigip)
                inner_active_found = True
                break
        except requests.exceptions.ConnectionError as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue
        except requests.exceptions.ReadTimeout as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue
        except requests.exceptions.ReadTimeoutError as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue
        except socket.timeout as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue
    if not inner_active_found:
        logger.log(logging.WARNING, "NO ACTIVE NODE FOUND FOR %s INNER" % region.upper())
        logger.log(logging.WARNING, "%s INNER WILL BE SKIPPED!" % region.upper())
    else:
        logger.log(logging.INFO, "* * * %s - INNER * * * " % region.upper())

        # Is inner pool node FQDN or IP?
        # Are inner pool nodes FQDN or IP? Evaluate all before creating pool.
        payload_members = []
        for member in inner_pool_members:
            try:
                addr, port = member.split(':')
                pool_format_node = member
                ipaddress.IPv4Address(addr)
                # Add IP Node to payload
                payload_members.append(member)
            except ipaddress.AddressValueError as e:
                logger.log(logging.INFO, "%s is not valid IP. Creating FQDN Node(s)..." % addr)
                # If its FQDN, we need to ensure node exists. If not we have to make it
                fqdn_node = {"name": addr, "fqdn": {"tmName": addr, "autopopulate": "enabled"}}
                #resp = create_node(conn, base_url, fqdn_node, proxies=proxies)
                resp = create_node(conn, base_url, fqdn_node)
                if resp.ok:
                    logger.log(logging.INFO, "Created FQDN node %s on %s" % (addr,bigip))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    payload_members.append(member)
                else:
                    logger.log(logging.WARNING, "Error during node creation: %s" % str(resp.content))
                    if resp.status_code == 409:
                        # FQDN Node already exists, we can re-use
                        payload_members.append(member)
                    else:
                        logger.log(logging.CRITICAL, "Problem adding or using node: %s, skipping node..." % member)
        if not payload_members:
            logger.log(logging.CRITICAL, "No validated nodes to create pool %s" % str(build_name + '.pool'))
            exit(1)
        #resp = create_pool(conn, base_url, str(build_name + '.pool'), payload_members, proxies=proxies)
        resp = create_pool(conn, base_url, str(build_name + '.pool'), payload_members)
        if resp.ok:
            logger.log(logging.INFO, "Created pool %s on %s" % (str(build_name + '.pool'), bigip))
            logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
        else:
            logger.log(logging.WARNING, "Error during pool creation: %s" % str(resp.content))
    
        # Create virtual server with standard settings 
        try:
            addr, port = inner_vs_ip, inner_vs_port
            vip_payload = {"name": str(build_name + '.vs'), "destination": str(addr + ':' + port), "ipProtocol": "tcp",
                           "pool": str(build_name + '.pool'), "source": "0.0.0.0/0", "vlansEnabled": True,
                           "vlans": ["/Common/Vlan_30"], "sourceAddressTranslation": {"pool": "/Common/inbound.sp", "type": "snat"},
                           "mask": "255.255.255.255", "enabled": True, "description": snap_ticket}
            #resp = create_vip(conn, base_url, vip_payload, proxies=proxies)
            resp = create_vip(conn, base_url, vip_payload)
            if resp.ok:
                logger.log(logging.INFO, "Created VIP %s on %s" % (str(build_name + '.vs'), bigip))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
            else:
                logger.log(logging.WARNING, "Error during VIP creation: %s" % str(resp.content))
        except BaseException as e:
            logger.log(logging.CRITICAL, "FATAL ERROR: Failed to create VIP %s - %s" % ((str(build_name + '.vs'), e)))
            logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
    
        # Is this passthrough or break and inspect?
        
        try:
            if build_type.lower() == "passthrough":
                #resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["fastL4"], proxies=proxies)
                resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["fastL4"])
            elif build_type.lower() == "breakandinspect":
                #resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["serverssl", "http"], proxies=proxies)
                resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["serverssl", "http"])
            else:
                logger.log(logging.CRITICAL, "Unknown build type: %s! Exiting...." % build_type)
            if resp.status_code != 200:
                logger.log(logging.WARNING, "Error applying profiles to %s" % str(build_name + '.vs'))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
        except BaseException as e:
                logger.log(logging.WARNING, "Error applying profiles to %s" % str(build_name + '.vs'))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
            
    
        logger.log(logging.INFO, "%s INNER objects completed." % region.upper())




    # Move on to Outer
    # Don't necessarily care if inner didnt get built. Can be re-ran or built manually

    logger.log(logging.INFO,"Moving to %s OUTER." % region.upper())

    outer_active_found = False
    for system in systems['cloud'][region]['outer']:
        bigip = system["name"]
        logger.log(logging.INFO, "Checking %s for active node..." % bigip)
        try:
            #conn, base_url = session_setup(bigip, username, pw, proxies=proxies)
            conn, base_url = session_setup(bigip, username, pw)
            #if local_node_is_active(conn, base_url, proxies=proxies):
            if not local_node_is_active(conn, base_url):
                continue
            else:
                logger.log(logging.INFO, "%s is active node - proceeding with build..." % bigip)
                outer_active_found = True
                break
        except requests.exceptions.ConnectionError as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue

    if not outer_active_found:
        logger.log(logging.WARNING, "NO ACTIVE NODE FOUND FOR %s OUTER!" % region.upper())
        logger.log(logging.WARNING, "%s OUTER WILL BE SKIPPED!" % region.upper())
    else:
        logger.log(logging.INFO, "* * * %s - OUTER * * * " % region.upper())
        
        # Create outer pool (will always be IP-based on Inner VS)
        addr, port = inner_vs_ip, inner_vs_port
        pool_format_node = [str(addr + ':' + port)] 
        #resp = create_pool(conn, base_url, str(build_name + '.pool'), pool_format_node, proxies=proxies)
        resp = create_pool(conn, base_url, str(build_name + '.pool'), pool_format_node)
        if resp.ok:
            logger.log(logging.INFO, "Created pool %s on %s" % (str(build_name + '.pool'), bigip))
            logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
        else:
            logger.log(logging.WARNING, "Error during pool creation: %s" % str(resp.content))
    
        # If this is a break and inspect, need to upload cert/key, create client-ssl profile
    
        '''
            resp = upload_file(conn, base_url, filename="notes2.txt", proxies = {"http": "http://proxy.some.domain.com:8080", "https": "http://proxy.some.domain.com:8443"})
            resp = move_file(conn, base_url, "notes2.txt", proxies = {"http": "http://proxy.some.domain.com:8080", "https": "http://proxy.some.domain.com:8443"})
            Hardcoded to move files from /var/config/rest/downloads to /shared/tmp (Only upload location to location with more disk space)
        '''
    
        # If client_ssl_override specifies an existing client ssl profile, use that and skip this section.
        if build_type.lower() == "breakandinspect" and client_ssl_override == "":
            
            certfile_without_path = os.path.basename(certfile)
            keyfile_without_path = os.path.basename(keyfile)
            # See if certificate/key with same name exists:
            reuse = ""
            #c_response = get_cert(conn, base_url, certfile_without_path, proxies=proxies)
            c_response = get_cert(conn, base_url, certfile_without_path)
            if c_response.ok:
                certfound = json.loads(c_response.content)
                logger.log(logging.WARNING, "Certificate already exists!")
                logger.log(logging.WARNING, "Found at: %s" % certfound['fullPath'])
                logger.log(logging.WARNING, "ISSUER: %s" % certfound['issuer'])
                logger.log(logging.WARNING, "SUBJECT: %s" % certfound['subject'])
                logger.log(logging.WARNING, "SANs: %s" % certfound['subjectAlternativeName'])
                logger.log(logging.WARNING, "FINGERPRINT: %s" % certfound['fingerprint'])
                logger.log(logging.WARNING, "EXPIRATION: %s" % certfound['expirationString'])
                logger.log(logging.WARNING, "Updated: %s" % certfound['lastUpdateTime'])
                logger.log(logging.WARNING, "Updated by: %s" % certfound['updatedBy'])
                reuse = input("\nDo you want to utilize this certifcate and associated key? [y\\n]: ")
                if not reuse.lower() == "y":
                    logger.log(logging.WARNING, "\n%s\n%s\n\n" % (certfile,keyfile))
                    overwrite = input("\nOverwrite found Certificate and associated key with above files? [y\\n]: ")
                    # If dont want to overwrite or reuse nothing to do. Otherwise if overwrite is selected script will continue as normal
                    if not overwrite.lower() == "y":
                        logger.log(logging.CRITICAL, "EXITING Due to Cert/KEY conflict.")
                        exit(1)
            # Upload crt/key
            if not reuse:
                #resp = upload_file(conn, base_url, filename=certfile, proxies=proxies)
                resp = upload_file(conn, base_url, filename=certfile)
                if resp.ok:
                    logger.log(logging.INFO, "Uploaded %s to %s" % (certfile, bigip))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error uploading certificate %s" % certfile)
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                #resp = upload_file(conn, base_url, filename=keyfile, proxies=proxies)
                resp = upload_file(conn, base_url, filename=keyfile)
                if resp.ok:
                    logger.log(logging.INFO, "Uploaded %s to %s" % (keyfile, bigip))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error uploading keyfile %s" % keyfile)
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                # Move to /shared/tmp (larger directory)
                #resp = move_file(conn, base_url, certfile_without_path, proxies=proxies)
                resp = move_file(conn, base_url, certfile_without_path)
                if resp.ok:
                    logger.log(logging.INFO, "Moved %s to /shared/tmp" % (certfile_without_path))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error moving certificate %s" % certfile)
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                #resp = move_file(conn, base_url, keyfile_without_path, proxies=proxies)
                resp = move_file(conn, base_url, keyfile_without_path)
                if resp.ok:
                    logger.log(logging.INFO, "Moved %s to /shared/tmp" % (keyfile_without_path))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error moving key %s to /shared/tmp" % certfile)
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                # Install cert/key file 
                #resp = install_cert(conn, base_url, certfile_without_path, proxies=proxies)
                resp = install_cert(conn, base_url, certfile_without_path)
                if resp.ok:
                    logger.log(logging.INFO, "Successfully installed certificate %s" % (certfile_without_path))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error installing cert %s on %s" % (certfile_without_path,bigip))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                #resp = install_key(conn, base_url, keyfile_without_path, proxies=proxies)
                resp = install_key(conn, base_url, keyfile_without_path)
                if resp.ok:
                    logger.log(logging.INFO, "Successfully installed key %s" % (keyfile_without_path))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error installing key %s on %s" % (keyfile_without_path,bigip))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
                # Create client-ssl profile - not providing any customizations right now. Will always inherit sec-baseline
                #resp = create_ssl_profile(conn, base_url, cert=certfile_without_path, key=keyfile_without_path, name=str(build_name + '.sslpro'), proxies=proxies)
                resp = create_ssl_profile(conn, base_url, cert=certfile_without_path, key=keyfile_without_path, name=str(build_name + '.sslpro'))
                if resp.ok:
                    logger.log(logging.INFO, "Successfully created client-ssl profile %s" % str(build_name + '.sslpro'))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error creating client-ssl profile on %s" % bigip)
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                    exit(1) 
            elif reuse.lower() == "y":
                # Use existing cert/key (skipped uploading/installing)
                #resp = create_ssl_profile(conn, base_url,  cert=certfile_without_path, key=keyfile_without_path, name=str(build_name + '.sslpro'), proxies=proxies)
                resp = create_ssl_profile(conn, base_url,  cert=certfile_without_path, key=keyfile_without_path, name=str(build_name + '.sslpro'))
                if resp.ok:
                    logger.log(logging.INFO, "Successfully created client-ssl profile %s" % str(build_name + '.sslpro'))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                else:
                    logger.log(logging.CRITICAL, "Error creating client-ssl profile on %s" % bigip)
       
    
        # Create outer VS
        try:
            addr, port = outer_vs_ip, outer_vs_port
            vip_payload = {"name": str(build_name + '.vs'), "destination": str(addr + ':' + port), "ipProtocol": "tcp",
                           "pool": str(build_name + '.pool'), "source": "0.0.0.0/0", "vlansEnabled": True,
                           "vlans": ["/Common/Outer", "/Common/Vlan_40"], "mask": "255.255.255.255", "enabled": True, "description": snap_ticket}
                           #"vlans": ["/Common/Outer"], "mask": "255.255.255.255", "enabled": True, "description": snap_ticket}
            #resp = create_vip(conn, base_url, vip_payload, proxies=proxies)
            resp = create_vip(conn, base_url, vip_payload)
            if resp.ok:
                logger.log(logging.INFO, "Created VIP %s on %s" % (str(build_name + '.vs'), bigip))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
            else:
                logger.log(logging.WARNING, "Error during VIP creation: %s" % str(resp.content))
        except BaseException as e:
                logger.log(logging.CRITICAL, "FATAL ERROR: Failed to create VIP %s - %s" % ((str(build_name + '.vs'), e)))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
                pdb.set_trace()
    
        # Add http_sec-baseline, client-ssl profiles if break and inspect, otherwise fastL4
        try:
            if build_type == "breakandinspect":
                if client_ssl_override:
                    #resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["http_sec-baseline", str(client_ssl_override), "standardwithbanner-PKIrules.accesspro"], proxies=proxies)
                    resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["http_sec-baseline", str(client_ssl_override), "standardwithbanner-PKIrules.accesspro"])
                else:
                    #resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["http_sec-baseline", str(build_name + '.sslpro'), "standardwithbanner-PKIrules.accesspro"], proxies=proxies)
                    resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["http_sec-baseline", str(build_name + '.sslpro'), "standardwithbanner-PKIrules.accesspro"]) 
            else:
                #resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["fastL4"], proxies=proxies)
                resp = add_profiles(conn, base_url, virtual_server=str(build_name + '.vs'), profiles=["fastL4"])
            if resp.status_code != 200:
                logger.log(logging.WARNING, "Error applying profiles to %s" % str(build_name + '.vs'))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
        except BaseException as e:
                logger.log(logging.WARNING, "Error applying profiles to %s" % str(build_name + '.vs'))
                logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
    
        # TODO Add sec-baseline cookie/header rules if break and inspect
        try:
            if build_type == "breakandinspect":
                #resp = add_rules(conn, base_url, virtual_server=str(build_name + '.vs'), rules=["sec-baseline_http-security-headers.irule",	"sec-baseline_http-security-cookie-settings.irule", "STD_APM_PKI-Extract.irule", "STD_APM_PKI-Headers-All_NOextensions.irule"], proxies=proxies)
                resp = add_rules(conn, base_url, virtual_server=str(build_name + '.vs'), rules=["sec-baseline_http-security-headers.irule",	"sec-baseline_http-security-cookie-settings.irule", "STD_APM_PKI-Extract.irule", "STD_APM_PKI-Headers-All_NOextensions.irule"])
                if resp.status_code != 200:
                    logger.log(logging.WARNING, "Error applying rules to %s" % str(build_name + '.vs'))
                    logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))
        except BaseException as e:
            logger.log(logging.WARNING, "Error applying rules to %s" % str(build_name + '.vs'))
            logger.log(logging.DEBUG, "\n%s\n" % str(resp.content))

def get_logger(name):

    logger = logging.getLogger(name)
    if not logger.handlers:
        logger.propagate = 0
        console = logging.StreamHandler()
        logfile = logging.FileHandler('pdss_builder_01.log')
        # Always log debug to file whether selected or not
        logfile.setLevel(logging.DEBUG)
        console.setLevel(logging.INFO)
        logger.addHandler(console)
        logger.addHandler(logfile)
        logger.setLevel(logging.DEBUG)
        c_format = logging.Formatter('%(asctime)s %(name)s - %(levelname)s - %(message)s')
        console.setFormatter(c_format)
        logfile.setFormatter(c_format)
    return logger

if __name__ == '__main__':
    main()


