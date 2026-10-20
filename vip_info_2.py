#!/usr/bin/python3

import re
import csv
import pdb
import json
import pprint
import getpass
import logging
import argparse
import ipaddress
from mike_f5 import *

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
    parser = argparse.ArgumentParser(description="Display arbitrary Virtual Server stats/info")
    parser.add_argument("-v", "--verbose", help="Display verbose output", required=False, action="store_true")
    parser.add_argument("-r", "--region", help="Which region to check. Valid options are 'east' or 'west'", required=True)
    args = parser.parse_args()
    region_vals = ["east", "west"]
        


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

    if not args.region.lower().strip() in region_vals:
        logger.log(logging.CRITICAL, str(f"Not a valid region: {args.region}"))
        exit(1)

    global pw
    pw = getpass.getpass("Cloud PW: ")

    outer_vip_info, address_lists  = check_region(args.region.lower().strip(), loglevel, "outer")
    if outer_vip_info:
        inner_vip_info = check_region(args.region.lower().strip(), loglevel, "inner")
    combined_vips = []
    for ovip in outer_vip_info:
        common_vip = {}
        match_found = False
        # For both inner and outer vip, convert to int and unpack ranges
        try:
            if len(ovip["innertarget"]) == 0:
                continue
            inner_target_port = int(ovip["innertarget"][0].split(':')[-1])
            inner_target_addr = str(ovip["innertarget"][0].split(':')[0])
            for ivip in inner_vip_info:
                if match_found:
                    break
                ivip_ports = set(expand_ranges(ivip["ports"]))
                if not inner_target_addr == ivip["address"]:
                    continue
                elif inner_target_port in ivip_ports or inner_target_port == 0 or 0 in ivip_ports:
                    # Found our match
                    match_found = True
                    common_vip["name"] = ovip["name"]
                    common_vip["outeraddr"] = ovip["address"]
                    common_vip["inneraddr"] = ivip["address"]
                    common_vip["backend"] = ivip["innertarget"]
                    common_vip["type"] = ovip["type"]
                    combined_vips.append(common_vip)
                    break
            if not match_found:
                common_vip["name"] = ovip["name"]
                common_vip["outeraddr"] = ovip["address"]
                common_vip["inneraddr"] = ""
                common_vip["backend"] = ""
                common_vip["type"] = ovip["type"]
                combined_vips.append(common_vip)
        except IndexError as e:
            pdb.set_trace()
        except ValueError as e:
            pdb.set_trace()
    # clean up address lists
    for vip in combined_vips:
        innertarget = ""
        vip["account"] = ""
        try:
            # Inner target is always a list
            # Just pick one and match against it
            innertarget = ipaddress.IPv4Address(vip["backend"][0].split(':')[0])
        except ipaddress.AddressValueError as e:
            print("5")
            vip["account"] = "Unknown"
            continue
        except IndexError as e:
            vip["account"] = "N/A"
            continue
        if innertarget:
            matched_nets = []
            for address_list in address_lists:
                address_list_name = address_list["name"]
                address_list_addresses = address_list["addresses"]
                address_list_ipobj = []
                for item in address_list_addresses:
                    if '/' in item['name']:
                        try:
                            address_list_ipobj.append(ipaddress.IPv4Network(item['name']))
                        except ipaddres.AddressValueError as e:
                            print("1")
                            pdb.set_trace()
                        except ipaddress.NetmaskValueError as e:
                            print("2")
                            pdb.set_trace()
                        except ValueError as e:
                            print("3")
                            pdb.set_trace()
                    else:
                        # Don't care about individual addresses
                        continue
                if not address_list_ipobj:
                    continue
                else:
                    for net in address_list_ipobj:
                        if innertarget in net:
                           matchnet = {}
                           matchnet["name"] = address_list_name
                           matchnet["network"] = address_list_ipobj
                           matched_nets.append(matchnet)
            if not matched_nets:
                vip["account"] = "Unknown"
            elif len(matched_nets) > 1:
                highest_prefix = 0
                highest_prefix_name = ""
                try:
                    for net in matched_nets:
                        name = net["name"]
                        netlist = net["network"]
                        for subnet in netlist:
                            if innertarget in subnet and subnet.prefixlen > highest_prefix:
                                highest_prefix = subnet.prefixlen
                                highest_prefix_name = name
                    vip["account"] = highest_prefix_name
                except AttributeError as e:
                    print("4")
                    pdb.set_trace()
            else:
                vip["account"] = matched_nets[0]["name"]

    
            
    
    #pprint.pprint(combined_vips)
    print(f"outer_vips: {len(outer_vip_info)}, inner_vips: {len(inner_vip_info)}, combined_vips: {len(combined_vips)}")
    pdb.set_trace()

    '''
    try:
        f = open("east_vips.csv", "w+")
        csv_writer = csv.DictWriter(f, fieldnames = ["name", "type", "address", "ports", "clientssl", "serverssl"] )
        csv_writer.writeheader()
        for obj in vip_info:
            csv_writer.writerow(obj)
        f.close()
    except BaseException as e:
        pdb.set_trace()

    vip_info  = check_region("west", loglevel)
    try:
        f = open("west_vips.csv", "w+")
        csv_writer = csv.DictWriter(f, fieldnames = ["name", "type", "address", "ports", "clientssl", "serverssl"] )
        csv_writer.writeheader()
        for obj in vip_info:
            csv_writer.writerow(obj)
        f.close()
    except BaseException as e:
        pdb.set_trace()
    '''

    try:
        f = open(str(f"combined_vips_{args.region.lower().strip()}.csv"), "w+")
        #f = open("combined_vips.csv", "w+")
        csv_writer = csv.DictWriter(f, fieldnames = ["account", "name", "type", "outeraddr", "inneraddr", "backend"])
        csv_writer.writeheader()
        for obj in combined_vips:
            csv_writer.writerow(obj)
        f.close()
    except BaseException as e:
        pdb.set_trace()


def check_region(region, loglevel, inner_or_outer="outer"):
    logger = get_logger(__name__)
    logger.setLevel(loglevel)


    # Setting up connection
    inner_or_outer_vals = ["inner", "outer"]
    if inner_or_outer not in inner_or_outer_vals:
        raise ValueError("Invalid inner/outer type. Expected one of: %s" % inner_or_outer_vals)
    active_found = False
    for system in systems['cloud'][region][inner_or_outer]:
        bigip = system["name"]
        logger.log(logging.INFO, "Checking %s for active node..." % bigip)
        try:
            #conn, base_url = session_setup(bigip, username, pw, proxies=proxies)
            conn, base_url = session_setup(bigip, username, pw)
            #if local_node_is_active(conn, base_url, proxies=proxies):
            if not local_node_is_active(conn, base_url):
                continue
            else:
                logger.log(logging.INFO, "%s is active node - pulling info..." % bigip)
                active_found = True
                break
        except requests.exceptions.ConnectionError as error:
            logger.log(logging.WARNING, "Connection to %s failed - %s" % (bigip, error))
            continue
    if not active_found:
        logger.log(logging.WARNING, "NO ACTIVE NODE FOUND FOR %s %s" % (region.upper(),inner_or_outer.upper()))
        logger.log(logging.WARNING, "%s %s WILL BE SKIPPED!" % (region.upper(),inner_or_outer.upper()))

    # Pull all VIPs and look at profiles
    resp = get_vips(conn, base_url, proxies=proxies)
    vips_list = [vip for vip in json.loads(resp.content)['items']]
    vip_info = []
    try:
        for vip in vips_list:
            #if vip["name"] == "dwprod.vs":
            #    pdb.set_trace()
            vip_dict = {}
            vip_dict["name"] = vip["name"]
            logger.log(logging.DEBUG, str(f"{bigip}, VIP: {vip['name']}"))
            vip_dict["address"] = ""
            vip_dict["ports"] = ""
            vip_dict["clientssl"] = []
            vip_dict["serverssl"] = []
            vip_dict["type"] = ""
            vip_dict["pool"] = ""
            for item in vip['profilesReference']['items']:
                try:
                    # Check for SSL profiles
                    if (item['context'] == 'clientside') and ('client-ssl' in item['nameReference']['link']):
                        vip_dict["clientssl"].append(item["name"])
                        vip_dict["address"] = re.sub(':.*', '', (re.sub('/Common/', '', vip["destination"])))
                        vip_dict["ports"] = [re.sub('.*:', '', (re.sub('/Common/', '', vip["destination"])))]
                        if not vip_dict["address"]:
                            resp = get_referenced_link(conn, bigip, \
                                   vip["trafficMatchingCriteriaReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["address"] = resp_content["destinationAddressInline"]
                            resp = get_referenced_link(conn, bigip, \
                                   resp_content["destinationPortListReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["ports"] = [port["name"] for port in resp_content["ports"]]
                    elif (item['context'] == 'serverside') and ('server-ssl' in item ['nameReference']['link']):
                        vip_dict["serverssl"].append(item["name"])
                        vip_dict["address"] = re.sub(':.*', '', (re.sub('/Common/', '', vip["destination"])))
                        vip_dict["ports"] = [re.sub('.*:', '', (re.sub('/Common/', '', vip["destination"])))]
                        if not vip_dict["address"]:
                            resp = get_referenced_link(conn, bigip, \
                                   vip["trafficMatchingCriteriaReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["address"] = resp_content["destinationAddressInline"]
                            resp = get_referenced_link(conn, bigip, \
                                   resp_content["destinationPortListReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["ports"] = [port["name"] for port in resp_content["ports"]]
                    # L4 is always passthrough
                    elif (item['context'] == 'all') and ('fastL4' in item['nameReference']['link']):
                        vip_dict["type"] = str(item["name"] + " Passthrough")
                        vip_dict["address"] = re.sub(':.*', '', (re.sub('/Common/', '', vip["destination"])))
                        vip_dict["ports"] = [re.sub('.*:', '', (re.sub('/Common/', '', vip["destination"])))]
                        if not vip_dict["address"]:
                            resp = get_referenced_link(conn, bigip, \
                                   vip["trafficMatchingCriteriaReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["address"] = resp_content["destinationAddressInline"]
                            resp = get_referenced_link(conn, bigip, \
                                   resp_content["destinationPortListReference"]["link"], '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            vip_dict["ports"] = [port["name"] for port in resp_content["ports"]]
                except KeyError as e:
                    continue
            # If we haven't already ID'd vip type, check which SSL profiles were found
            if not vip_dict["clientssl"] and not vip_dict["serverssl"] and not vip_dict["type"]:
                vip_dict["address"] = re.sub(':.*', '', (re.sub('/Common/', '', vip["destination"])))
                vip_dict["ports"] = [re.sub('.*:', '', (re.sub('/Common/', '', vip["destination"])))]
                if not vip_dict["address"]:
                    resp = get_referenced_link(conn, bigip, \
                            vip["trafficMatchingCriteriaReference"]["link"], '', proxies=proxies)
                    resp_content = json.loads(resp.content)
                    vip_dict["address"] = resp_content["destinationAddressInline"]
                    resp = get_referenced_link(conn, bigip, \
                            resp_content["destinationPortListReference"]["link"], '', proxies=proxies)
                    resp_content = json.loads(resp.content)
                    vip_dict["ports"] = [port["name"] for port in resp_content["ports"]]
            if len(vip_dict["clientssl"]) == 0 and len(vip_dict["serverssl"]) == 0:
                vip_dict["type"] = "Standard Passthrough"
            elif len(vip_dict["clientssl"]) >= 1 and len(vip_dict["serverssl"]) >= 1:
                vip_dict["type"] = "Re-encrypt Passthrough"
            elif len(vip_dict["clientssl"]) >= 1 and len(vip_dict["serverssl"]) == 0:
                vip_dict["type"] = "Break and Inspect"
            elif len(vip_dict["clientssl"]) == 0 and len(vip_dict["serverssl"]) >=1:
                vip_dict["type"] = "Break and Inspect"

            # Find Inner address to assist with pool tracing to cloud
            vip_dict["pool"] = ""
            vip_dict["poollink"] = ""
            vip_dict["innertarget"] = []
            try:
                vip_dict["pool"] = vip["pool"].replace('/Common/', '')
                vip_dict["poollink"] = vip["poolReference"]["link"]
                resp = get_referenced_link(conn, bigip, vip_dict["poollink"], '', proxies=proxies)
                resp_content = json.loads(resp.content)
                resp = get_referenced_link(conn, bigip, resp_content["membersReference"]["link"], '', proxies=proxies) 
                resp_content = json.loads(resp.content) 
                #if vip["name"] == "devsso.ois.navy.mil.vs": #pdb.set_trace()
                for node in resp_content["items"]:
                    if "disabled" in node["session"]:
                        continue 
                    fullpath = node["fullPath"] 
                    if node["address"] == "::" or node["address"] == "any6":
                        continue
                    if not node["address"] == re.sub('/Common/', '', fullpath).split(':')[0]:
                        vip_dict["innertarget"].append(str(node["address"] + ':' + re.sub('/Common/', '', fullpath).split(':')[-1]))
                    else:
                        vip_dict["innertarget"].append(re.sub('/Common/', '', fullpath))
            except KeyError as e:
                pass
            # Find policy or irule backend references if default pool is not set
            if inner_or_outer == "inner" and not vip_dict["innertarget"]:
                logger.log(logging.DEBUG, str(f"Trying policy trace for {vip['name']}"))
                try:
                    vip_policies = vip["policiesReference"]["items"]
                    for policyref in vip_policies:
                        if vip_dict["innertarget"]:
                            break
                        reflink = policyref["nameReference"]["link"]
                        resp = get_referenced_link(conn, bigip, reflink, '', proxies=proxies)
                        resp_content = json.loads(resp.content)
                        if "forwarding" in resp_content["controls"]:
                            reflink = resp_content["rulesReference"]["link"]
                            resp = get_referenced_link(conn, bigip, reflink, '', proxies=proxies)
                            resp_content = json.loads(resp.content)
                            for rule in resp_content["items"]:
                                if vip_dict["innertarget"]:
                                    break
                                reflink = rule["actionsReference"]["link"]
                                resp = get_referenced_link(conn, bigip, reflink, '', proxies=proxies)
                                resp_content = json.loads(resp.content)
                                for actionprop in resp_content["items"]:
                                    if vip_dict["innertarget"]:
                                        break
                                    try:
                                        poolref = actionprop["poolReference"]["link"]
                                    except KeyError as e:
                                        try:
                                            node = actionprop["node"]
                                            vip_dict["innertarget"].append(node)
                                            break
                                        except KeyError as e:
                                            continue
                                    else:
                                        resp = get_referenced_link(conn, bigip, poolref, '', proxies=proxies)
                                        resp_content = json.loads(resp.content)
                                        resp = get_referenced_link(conn, bigip, resp_content["membersReference"]["link"])
                                        resp_content = json.loads(resp.content)
                                        for node in resp_content["items"]:
                                            if "disabled" in node["session"]:
                                                continue 
                                            if node["address"] == "::" or node["address"] == "any6":
                                                continue
                                            fullpath = node["fullPath"] 
                                            if not node["address"] == re.sub('/Common/', '', fullpath).split(':')[0]:
                                                vip_dict["innertarget"].append( str(node["address"] + ':' + re.sub('/Common/', '', fullpath).split(':')[-1]))
                                                break
                                            else:
                                                vip_dict["innertarget"].append(re.sub('/Common/', '', fullpath))
                                                break
                except KeyError as e:
                    pass
            if inner_or_outer == "inner" and not vip_dict["innertarget"]:
                logger.log(logging.DEBUG, str(f"Trying irule trace for {vip['name']}"))
                #pdb.set_trace()
                # No pool found for policy. Try iRules
                # Looks for 'pool <poolname.pool>' strings in irule text. If poolname.pool is LTM obj, find node addr
                pat = re.compile(r'^(?!#).+(pool)(\s*)(.*\.pool)')
                try:
                    rules = vip["rules"]
                    for rule in rules:
                        if vip_dict["innertarget"]:
                            break
                        if "sec-baseline" in rule or "_sys_" in rule or "STD" in rule:
                            continue
                        resp = get_irule(conn, base_url, rule, proxies=proxies)
                        resp_content = json.loads(resp.content)
                        rule_data = resp_content['apiAnonymous']
                        rule_lines = rule_data.split('\n')
                        for line in rule_lines:
                            if vip_dict["innertarget"]:
                                break
                            mo = re.match(pat, line)
                            if mo:
                                poolstring = mo.groups()[-1]
                                resp = get_pool(conn, base_url, poolstring, proxies=proxies)
                                resp_content = json.loads(resp.content)
                                #resp = get_referenced_link(conn, bigip, resp_content["membersReference"]["link"])
                                #resp_content = json.loads(resp.content)
                                for node in resp_content["membersReference"]["items"]:
                                    if "disabled" in node["session"]:
                                        continue 
                                    if node["address"] == "::" or node["address"] == "any6":
                                        continue
                                    fullpath = node["fullPath"] 
                                    if not node["address"] == re.sub('/Common/', '', fullpath).split(':')[0]:
                                        vip_dict["innertarget"].append( str(node["address"] + ':' + re.sub('/Common/', '', fullpath).split(':')[-1]))
                                        break
                                    else:
                                        vip_dict["innertarget"].append(re.sub('/Common/', '', fullpath))
                                        break
                except KeyError as e:
                    pass
            vip_info.append(vip_dict)
    except BaseException as e:
        #pdb.set_trace()
        pass
    address_lists = []
    if inner_or_outer == "outer":
        resp = get_address_lists(conn, base_url)
        resp_content = json.loads(resp.content)
        address_lists = resp_content['items']
    conn.close()
    if address_lists:
        return vip_info, address_lists
    else:
        return vip_info

def expand_ranges(input_list):
    result_list = []
    for item in input_list:
        if '-' in item:
            lower_str, higher_str = item.split('-')
            lower = int(lower_str)
            higher = int(higher_str)
            result_list.extend(range(lower, higher+1))
        else:
            result_list.append(int(item))
    return result_list

    
if __name__ == "__main__":
    main()

