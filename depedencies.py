import os
import time

Y = set(['yes', 'y', 'YES' ,'Y'])
N = set(['no', 'n', 'NO', 'N'])

os.system("figlet INSTALLATION")
agree = input("This tool needs some depedencies are you sure you want to install them Y / N ")

def agreementdown():
  if agree in Y:
    os.system("figlet INSTALLING")
    os.system("git clone https://github.com/thehackingsage/hacktronian.git")
    os.system("cd hacktronian")
    os.system("chmod +x hacktronian")
    os.system("sudo cp os.system /usr/bin")
    os.system("rm hacktronian")
    os.system("pip3 install urllib2")
  elif agree in N:
    print("This tool need some depedencies please run depedencies.py")
    print("Exiting")
    exit()

agreementdown()
