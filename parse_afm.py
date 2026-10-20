#!/usr/bin/python3

import csv
import pdb
import sys
import csv
import json
import pprint
import getpass
from mike_f5 import *

username = "removed"
pw = getpass.getpass()
bigip = sys.argv[-2]
rule_listname = sys.argv[-1]

def main():

    rule_list = []

    conn, base_url = session_setup(bigip, username, pw)
    if local_node_is_active(conn, base_url):
        mod_url = base_url + str(f"/tm/security/firewall/rule-list/{rule_listname}?expandSubcollections=true")
        resp = conn.get(mod_url)
        if not resp.ok:
            # Implement logging at some point
            exit(1)
        jp = json.loads(resp.content)
        rule_list = jp['rulesReference']['items']
        print(type(rule_list))
        f = open(f'afm_{rule_listname}.csv', 'w+')
        csv_writer = csv.DictWriter(f, fieldnames = ['name', 'action', 'proto', 'sourceaddr', 'sourceport', 'destaddr', 'destport'])
        csv_writer.writeheader()
        try:
            for rule in rule_list:
                rule_obj = {}
                rule_obj['name'] = rule['name']
                rule_obj['action'] = rule['action']
                rule_obj['proto'] = ""
                rule_obj['sourceaddr'] = ""
                rule_obj['sourceport'] = ""
                rule_obj['destaddr'] = ""
                rule_obj['destport'] = ""
                try:
                    assert rule['ipProtocol']
                    rule_obj['proto'] = rule['ipProtocol']
                except KeyError as e:
                    rule_obj['proto'] = "any"
                try:
                    assert rule['source']
                    if 'addressLists' in rule['source'].keys():
                        for reflink in rule['source']['addressListsReference']:
                            resp = get_referenced_link(conn, bigip, reflink['link'])
                            if not resp.ok:
                                # try one more time
                                resp = get_referenced_link(conn, bigip, reflink['link'])
                                if not resp.ok:
                                    print(resp.content)
                                    pdb.set_trace()
                                    exit(1)
                            reflink_json = json.loads(resp.content)
                            for address in reflink_json['addresses']:
                                rule_obj['sourceaddr'] += str(f'{address["name"]}' + " ")
                    elif 'addresses' in rule['source'].keys():
                        for address in rule['source']['addresses']:
                            rule_obj['sourceaddr'] += str(f'{address["name"]}' + " ")
                    else:
                        rule_obj['sourceaddr'] = rule['source']
                except KeyError as e:
                    rule_obj['sourceaddr'] = "any"
                try:
                    assert rule['destination']
                    if 'addressLists' in rule['destination'].keys():
                        for reflink in rule['destination']['addressListsReference']:
                            resp = get_referenced_link(conn, bigip, reflink['link'])
                            if not resp.ok:
                                # try one more time
                                resp = get_referenced_link(conn, bigip, reflink['link'])
                                if not resp.ok:
                                    print(resp.content)
                                    pdb.set_trace()
                                    exit(1)
                            reflink_json = json.loads(resp.content)
                            for address in reflink_json['addresses']:
                                rule_obj['destaddr'] += str(f'{address["name"]}' + " ")
                    elif 'addresses' in rule['destination'].keys():
                        for address in rule['destination']['addresses']:
                            rule_obj['destaddr'] += str(f'{address["name"]}' + " ")
                    else:
                        rule_obj['destaddr'] = "any"
                except KeyError as e:
                    rule_obj['destaddr'] = "any"
                try:
                    if 'portLists' in rule['destination'].keys():
                        for reflink in rule['destination']['portListsReference']:
                            resp = get_referenced_link(conn, bigip, reflink['link'])
                            if not resp.ok:
                                # try one more time
                                resp = get_referenced_link(conn, bigip, reflink['link'])
                                if not resp.ok:
                                    print(resp.content)
                                    pdb.set_trace()
                                    exit(1)
                            reflink_json = json.loads(resp.content)
                            for port in reflink_json['ports']:
                                rule_obj['destport'] += str(f'{port["name"]}' + " ")
                    elif 'ports' in rule['destination'].keys():
                        for port in rule['destination']['ports']:
                            rule_obj['destport'] += str(f'{port["name"]}' + " ")
                    else:
                        if rule_obj['proto'].lower() == "tcp" or rule_obj['proto'].lower() == "udp":
                            rule_obj['destport'] = "any"
                except KeyError as e:
                    rule_obj['destport'] = "any"
                except BaseException as b:
                    print(b)
                    pdb.set_trace()
                print(rule_obj['name'] )
                print(rule_obj['action'] )
                print("sourceaddr debug")
                print(rule_obj['sourceaddr'] )
                print("destaddr debug")
                print(rule_obj['destaddr'] )
                print("destport debug")
                print(rule_obj['destport'] )
                csv_writer.writerow(rule_obj)
                
        except json.decoder.JSONDecodeError as e:
                print("In JSON Exception trap - wtf happened?")
                print(e)
                pdb.set_trace()
        except TypeError as e:
            print("In TypeError - wtf happened?")
            print(e)
            pdb.set_trace()

if __name__ == "__main__":
    main()
