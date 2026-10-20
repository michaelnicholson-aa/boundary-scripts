#!/usr/bin/python3

import re
import pdb
import argparse


def main():

    parser = argparse.ArgumentParser(description="Tool to generate powershell commands for flipping AD DNS between regions")
    parser.add_argument("-z", "--zonename", help="Specify zone name (e.g. some.domain.com)", required=True)
    parser.add_argument("-f", "--zonefile", help="Exported zone list (text only)", required=True)
    parser.add_argument("-r", "--region", help="Target region", required=True, choices=["east", "west",])
    args = parser.parse_args()

    print(f"Changing {args.zonename.upper()} to region {args.region.upper()} using file {args.zonefile.upper()} as the initial baseline")

    with open(args.zonefile, 'r') as ZONEFILE:
        zonefile_lines = ZONEFILE.readlines()

    # Leave these alone, they should not change
    awest_pat = re.compile(r'.*-west,Host\s*\(A\)',re.IGNORECASE)
    aeast_pat = re.compile(r'.*-east,Host\s*\(A\)',re.IGNORECASE)

    # These will change to flip between the east and west A targets
    cnamewest_pat = re.compile(r'.*,Alias\s*\(CNAME\),.*-west',re.IGNORECASE)
    cnameeast_pat = re.compile(r'.*,Alias\s*\(CNAME\),.*-east',re.IGNORECASE)

    # Standard A records that point at PDSS, these will be deleted and recreated for the target region
    pdsswest_pat = re.compile(r'.*192\.168\.(224|225|226|227).*')
    pdsseast_pat = re.compile(r'.*192\.168\.(208|209|210|211).*')

    # DNS Servers
    dnsserver = ""
    if args.zonename == "someother.domain.com":
        dnsserver = "ndc2-1.someother.domain.com"
    elif args.zonename == "some.domain.com":
        dnsserver = "ndc1-22.some.domain.com"
    


    '''
    Google AI Gift - translate map is a joined string of all keys in dict pdss_map. In the build/add strings, we are using the sub function of the compiled pattern "pdss_translatemap"
    Using the pattern's sub function, we are effectively doing: result = compiled_pattern.sub(replacement, string)
    replacement, instead of just being text itself, is calling a function that returns a replacement string by checking the pdss_map[key] for the key found in the string
    this is only possible when the original pattern, ".208." for example, is found in the original string. Once this pattern is found, the match object is .208. and fed into the 
    pdss_translate function which pulls the value of the key ".208." in the pdss_map
    '''
    pdss_map = {".208.": ".224.", ".209.": ".225.", ".210.": ".226.", ".211.": ".227.", ".224.": ".208.", ".225.": ".209.", ".226.": ".210.", ".227.": ".211."}
    pdss_translatemap = re.compile("|".join(re.escape(key) for key in pdss_map.keys()))
    def pdss_translate(match):
        return pdss_map[match.group(0)]

    # Debugging
    for line in zonefile_lines:
        if re.match(awest_pat, line.lower()):
            # Leave these alone
            print("west A record")
            print(line)
        elif re.match(aeast_pat, line.lower()):
            # Leave these alone
            print("east A record")
            print(line)
        elif re.match(cnamewest_pat, line.lower()):
            print("west CNAME record")
            print(line)
            if args.region == "east":
                print(f"remove-dnsserverresourcerecord -zonename {args.zonename} {line.lower().split(',')[0]} -rrtype CNAME -computername {dnsserver} -force")
                print(f"add-dnsserverresourcerecordcname -zonename {args.zonename} -name {line.lower().split(',')[0]} -hostnamealias {line.lower().split(',')[0] + '-' + args.region} -computername {dnsserver}")
        elif re.match(cnameeast_pat, line.lower()):
            print("east CNAME record")
            print(line)
            if args.region == "west":
                print(f"remove-dnsserverresourcerecord -zonename {args.zonename} {line.lower().split(',')[0]} -rrtype CNAME -computername {dnsserver} -force")
                print(f"add-dnsserverresourcerecordcname -zonename {args.zonename} -name {line.lower().split(',')[0]} -hostnamealias {line.lower().split(',')[0] + '-' +  args.region} -computername {dnsserver}")
        elif re.match(pdsswest_pat, line.lower()):
            print("west PDSS record")
            print(line)
            if args.region == "east":
                print(f"remove-dnsserverresourcerecord -zonename {args.zonename} {line.lower().split(',')[0]} -rrtype A -computername {dnsserver} -force")
                print(f"add-dnsserverresourcerecordA -zonename {args.zonename} -name {line.lower().split(',')[0]} -IPv4Address {pdss_translatemap.sub(pdss_translate,line.lower().split(',')[2])} -computer {dnsserver}")
        elif re.match(pdsseast_pat, line.lower()):
            print("east PDSS record")
            print(line)
            if args.region == "west":
                print(f"remove-dnsserverresourcerecord -zonename {args.zonename} {line.lower().split(',')[0]} -rrtype A -computername {dnsserver} -force")
                print(f"add-dnsserverresourcerecordA -zonename {args.zonename} -name {line.lower().split(',')[0]} -IPv4Address {pdss_translatemap.sub(pdss_translate,line.lower().split(',')[2])} -computer {dnsserver}")

    


    #pdb.set_trace()



if __name__ == '__main__':
    main()
