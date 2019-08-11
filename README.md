
# Overview
**OneShot** performs [Pixie Dust attack](https://forums.kali.org/showthread.php?24286-WPS-Pixie-Dust-Attack-Offline-WPS-Attack) without having to switch to monitor mode.

# Requirements
 - Python 3.5 and above;
 - [Wpa supplicant](https://www.w1.fi/wpa_supplicant/);
 - [Pixiewps](https://github.com/wiire-a/pixiewps).

# Setup
## Debian/Ubuntu
**Installing requirements**
 ```
 sudo apt install -y python3 wpasupplicant wget
 ```
**Installing Pixiewps**

***Ubuntu 18.04 an above or Debian 10 and above***
 ```
 sudo apt install -y pixiewps
 ```
 
***Other versions***
 ```
 sudo apt install -y build-essential unzip
 wget https://github.com/wiire-a/pixiewps/archive/master.zip && unzip master.zip
 cd pixiewps*/
 make
 sudo make install
 ```
**Getting OneShot**:
 ```
 cd ~
 wget https://raw.githubusercontent.com/drygdryg/OneShot/master/oneshot.py
 ```

# Usage
```
 python3 oneshot.py <arguments>
 Required Arguments:
    -i, --interface=<wlan0>  : Name of the interface to use
    -b, --bssid=<mac>        : BSSID of the target AP

Optional Arguments:
    -p, --pin=<wps pin>      : Use the specified pin (arbitrary string or 4/8 digit pin)
    -K, --pixie-dust         : Run pixiedust attack
    -v                       : Verbose output
 ```

## Usage example
 ```
 sudo python3 oneshot.py -i wlan0 -b 00:90:4C:C1:AC:21 -K
 ```
