import Setup.setup as setup
import modules.attacks as attacks
import os
import sys

def max_index(dictionary):
    '''
    returns the bigger index < 98 on the current menu
    :param dictionary:
    :return: maxIndex: int
    '''
    keys = list(dictionary.keys())
    L = []
    for key in keys:
        if key < 98:
            L.append(key)
    return max(L)

class Directory:

    def __init__(self, dict ,flag):
        self.dict = dict
        self.flag = flag

    def show(self):
        for key in self.dict:
            print(" {%d}--%s" % (key, self.dict[key]))

    def change_directory(self, newDict, newFlag):
        self._oldFlag = self.flag
        self.dict = newDict
        self.flag = newFlag

    def clearScr():
        """
        clear the screen in case of GNU/Linux or
        windows
        """
        if system() == 'Linux':
            os.system('clear')
        if system() == 'Windows':
            os.system('cls')

    def logo():
        print """
                               - Powered by
     ___  ___       _____  ___  _____  _____
    |  \/  |      /  ___|/ _ \|  __ \|  ___|
    | .  . |_ __  \ `--./ /_\ \ |  \/| |__
    | |\/| | '__|  `--. \  _  | | __ |  __|
    | |  | | |_   /\__/ / | | | |_\ \| |___
    \_|  |_/_(_)  \____/\_| |_/\____/\____/
    """


    hacktronianlogo = """\033[0m
      _   _    _    ____ _  _______ ____   ___  _   _ ___    _    _   _
     | | | |  / \  / ___| |/ /_   _|  _ \ / _ \| \ | |_ _|  / \  | \ | |
     | |_| | / _ \| |   | ' /  | | | |_) | | | |  \| || |  / _ \ |  \| |
     |  _  |/ ___ \ |___| . \  | | |  _ <| |_| | |\  || | / ___ \| |\  |
     |_| |_/_/   \_\____|_|\_\ |_| |_| \_\_ __/|_| \_|___/_/   \_\_| \_|
     \033[91m"""

class Router:

    def __init__(self, dire,directories, links,  attack):
        self.dire = dire
        self.dirS = directories
        self.links = links
        self.attack = attack

    def start(self):

        while 1:
            self.dire.logo()
            self.dire.show()
            try:
                x = int(input('>> '))
            except KeyboardInterrupt:
                sys.exit()
            except:
                print('\nInput must be an iteger')
                continue

            if x == 99:
                sys.exit(0)
            elif x == 98:
                self.dire.change_directory(self.dirS[self.dire._oldFlag], self.dire._oldFlag)
                self.dire.clear_screen()
                continue

            elif x > max_index(self.dire.dict):
                print('\n[-]',x,"is not a valid argument\n")
                continue
            if any(self.links[i][0] in list(self.dire.dict.values()) and x == self.links[i][1] for i in range(len(self.links))):

            #if self.links[0][0] in list(self.dire.dict.values()) and x == self.links[0][1]:
                self.dire.change_directory(self.dirS[x],x)
            else:
                self.attack.name = self.dire.dict[x]
                self.attack.run()
                #break
            self.dire.clearScr()

class Attack:

    def __init__(self, dire):
        self.dire = dire

    def run(self):
        self.dire.clearScr()

        if self.name == "Private Web Hacking":
            attacks.dzz()
        elif self.name == "0":
            attacks.updatehacktronian()

        elif self.name == 'Shell Checker':
            attacks.sitechecker()
        elif self.name == 'POET':
            attacks.poet()
        elif self.name == "Phishing Framework":
            attacks.weeman()

        elif self.name == 'Drupal Hacking':
            attacks.maine()
        elif self.name == 'Inurlbr':
            attacks.ifinurl()
        elif self.name == "Wordpress & Joomla Scanner":
            attacks.wppjmla()
        elif self.name == "Gravity Form Scanner":
            attacks.gravity()
        elif self.name == "Wordpress Exploit Scanner":
            attacks.sqlscan()
        elif self.name == "Wordpress Plugins Scanner":
            attacks.wppluginscan()
        elif self.name == "Shell and Directory Finder":
            attacks.shelltarget()
        elif self.name == "Joomla! 1.5 - 3.4.5 remote code execution":
            attacks.joomlarce()
        elif self.name == "Vbulletin 5.X remote code execution":
            attacks.vbulletinrce()
        elif self.name == "BruteX - Automatically brute force all services running on a target":
            attacks.brutex()
        elif self.name == "Arachni - Web Application Security Scanner Framework":
            attacks.arachni()

        elif self.name == "Cupp":
            attacks.cupp()
        elif self.name == "Ncrack":
            attacks.ncrack()

        elif self.name == 'reaver':
            attacks.reaver()
        elif self.name == "pixiewps":
            attacks.pixiewps()
        elif self.name =='Bluetooth Honeypot GUI Framework':
            attacks.bluepot()
        elif self.name == "Fluxion":
            attacks.fluxion()

        elif self.name == "Nmap":
            attacks.nmap()
        elif self.name == "Port Scanning":
            attacks.ports()
        elif self.name == "Host To IP":
            attacks.h2ip()
        elif self.name == "wordpress user":
            attacks.wpue()
        elif self.name == "CMS scanner":
            attacks.cmsscan()
        elif self.name == "XSStrike":
            attacks.XSStrike()
        elif self.name == "Dork - Google Dorks Passive Vulnerability Auditor":
            attacks.doork()
        elif self.name == "Scan A server's Users":
            attacks.scanusers()
        elif self.name == "Crips":
            attacks.crips()

        elif self.name == 'Setoolkit':
            attacks.setoolkit()
        elif self.name == 'SSLtrip':
            attacks.ssls()
        elif self.name == "pyPISHER":
            attacks.pisher()
        elif self.name == "SMTP Mailer":
            attacks.smtpsend()

        elif self.name == "ATSCAN":
            attacks.atscan()
        elif self.name == "sqlmap":
            attacks.sqlmap()
        elif self.name == "Shellnoob":
            attacks.shellnoob()
        elif self.dire == 'commix':
            attacks.commix()
        elif self.name == "FTP Auto Bypass":
            attacks.gabriel()
        elif self.name == "jboss-autopwn":
            attacks.jboss()
        elif self.name == "Blind SQL Automatic Injection And Exploit":
            attacks.bsqlbf()
        elif self.name == "Bruteforce the Android Passcode given the hash and salt":
            attacks.androidhash()
        elif self.name == "Joomla SQL injection Scanner":
            attacks.cmsfew()
