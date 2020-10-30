import os
import subprocess
import re
import pwd
import time
import yaml

reported = []

with open("/etc/portauthority/portauthority.conf", "r") as yamlfile:
    cfg = yaml.load(yamlfile)

safeusers = cfg['behavior']['exempt']
badports = cfg['behavior']['badports']
killbad = cfg['behavior']['killbadports']
print(badports)

RE_NETSTAT = re.compile(r"tcp6? + [0-9] +[0-9] +([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:|:::)([0-9]{1,5}) + ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:|:::)(\*|[0-9]{1,5}) + (LISTEN|ESTABLISHED) + ([0-9]{1,}) + ([0-9]{1,9}) + ([0-9]{1,})(\/\.\/|\/)([a-zA-Z0-9]{1,})")

def logfile(msg):
    with open('/var/log/portauthority.log', 'a') as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")

logfile("Port authority daemon started")

def isuserport(uid, port):
    if pwd.getpwuid(int(uid)).pw_name in safeusers or int(uid) < 999:
        return True
    uport = 7000 + int(uid)
    if port is not uport:
        return False
    else:
        return True

while True:
    popen = subprocess.Popen(['netstat', '-natpe'],
                             shell=False,
                             stdout=subprocess.PIPE,
                             universal_newlines=True)
    (data, err) = popen.communicate()
    for line in list(str(data).split('\n')):
        match = re.search(RE_NETSTAT, line)
        if match:
            local, port, foriegn, fport, state, uid, inode, pid, _dir, pname = match.groups()
            if not isuserport(uid, port) and 'unassigned' in badports and not pid in reported:
                uname = pwd.getpwuid(int(uid)).pw_name
                logfile(f"The user {uname} (UID: {uid}) is attempting to run {pname} (PID: {pid}) outside of their assigned port (PORT: {port}).")
                reported.append(pid)
                if killbad:
                    os.system('kill ' + pid)
            elif port in badports and not pwd.getpwuid(int(uid)).pw_name in safeusers and int(uid) > 999 and not pid in reported:
                uname = pwd.getpwuid(int(uid)).pw_name
                logfile(f"The user {uname} (UID: {uid}) is attempting to run {pname} (PID: {pid}) on a banned port (PORT: {port}).")
                reported.append(pid)
                if killbad:
                    os.system('kill ' + pid)
    time.sleep(10)
