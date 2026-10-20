#!/usr/bin/env python

import datetime
import pexpect
import sys
import re

user = "removed"
outdir = "/removed/config-backups/cisco/"
#outdir = "/tmp/"
host = sys.argv[1]
# lol
date = datetime.datetime.strftime(datetime.datetime.today(), "%Y%m%d")
# unsafe prompt
nexus_prompt = "# "
#config_on_disk = "Warning: There is already a file existing with this name. Do you want to overwrite (y/n)?[n] "
# ^MWarning: There is already a file existing with this name. Do you want to overwrit^Hte (y/n)?[n] $
config_on_disk = re.compile(r'.*Warning: There is already a file existing with this name.*[n]')
# permission deny will return normal prompt -- will just exit and pull anyway
permission_deny = re.compile(r'Permission denied. Cannot overwrite existing file.')


child = pexpect.spawn("ssh -o StrictHostKeyChecking=no -o KexAlgorithms=diffie-hellman-group14-sha1 {}@{}".format(user,host))
index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
if index == 0:
    child.send("sh run | i hostname\n")
    index = child.expect([nexus_prompt, pexpect.EOF, pexpect.TIMEOUT])
    if index == 0:
        hostname = child.before.split('\n')[-1].lstrip()
        logfilename = str("/removed/config-backups/cisco/expect-logs/{}-pullconfig-{}.log".format(hostname,date))
        #logfilename = str("/tmp/{}-pullconfig-{}.log".format(hostname,date))
        logfile = open(logfilename, 'w')
        child.logfile = logfile
        # safer prompt
        nexus_prompt = str(hostname + '# ')
        child.send("copy running-config {}-{}.txt\n".format(hostname,date))
        index = child.expect([nexus_prompt, config_on_disk, pexpect.EOF, pexpect.TIMEOUT])
        if index == 0:
            child.send("exit\n")
            # pull the config
            a = pexpect.run("sftp {}@{}:{}-{}.txt {}".format(user,host,hostname,date,outdir))
        elif index == 1:
            # dont overwrite
            child.send("n\n")
            index = child.expect([nexus_prompt, config_on_disk, pexpect.EOF, pexpect.TIMEOUT])
            if index == 0:
                # pull the config
                a = pexpect.run("sftp {}@{}:{}-{}.txt {}".format(user,host,hostname,date,outdir))
child.close()
logfile.close()
print(nexus_prompt)
