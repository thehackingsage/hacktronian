#!/bin/bash
clear

BLACK='\e[30m'
RED='\e[31m'
GREEN='\e[32m'
YELLOW='\e[33m'
BLUE='\e[34m'
PURPLE='\e[35m'
CYAN='\e[36m'
WHITE='\e[37m'
NC='\e[0m'
echo""
echo -e "${RED} _   _   ___  _____  _   _____________ _____ _   _ _____  ___   _   _  "
echo " | | | | / _ \/  __ \| | / /_   _| ___ \  _  | \ | |_   _|/ _ \ | \ | | "
echo " | |_| |/ /_\ \ /  \/| |/ /  | | | |_/ / | | |  \| | | | / /_\ \|  \| | "
echo " |  _  ||  _  | |    |    \  | | |    /| | | | . ` | | | |  _  || . ` | "
echo " | | | || | | | \__/\| |\  \ | | | |\ \\ \_/ / |\  |_| |_| | | || |\  | "
echo " \_| |_/\_| |_/\____/\_| \_/ \_/ \_| \_|\___/\_| \_/\___/\_| |_/\_| \_/ "
echo -e "${NC}"
echo -e "${RED}                               ~ Tools for Hacking by Mr. SAGE ${NC}"
echo ""
echo -e "${YELLOW} Twitter.com/thehackingsage | Instagram.com/thehackingsage | Github.com/thehackingsage ${NC} "
echo ""
echo "---------------------------------------------------------------------------------"
echo ""
echo -e "${CYAN}[>] Press ENTER to Install, CTRL+C to Abort.${NC}"
read INPUT
echo ""

if [ "$PREFIX" = "/data/data/com.termux/files/usr" ]; then
    INSTALL_DIR="$PREFIX/usr/share/doc/hacktronian"
    BIN_DIR="$PREFIX/usr/bin/"
    pkg install -y git python2
else
    INSTALL_DIR="/usr/share/doc/hacktronian"
    BIN_DIR="/usr/bin/"
fi

echo "[✔] Checking directories...";
if [ -d "$INSTALL_DIR" ]; then
    echo "[◉] A directory hacktronian was found! Do you want to replace it? [Y/n]:" ;
    read mama
    if [ "$mama" = "y" ]; then
        rm -R "$INSTALL_DIR"
    else
        exit
    fi
fi

echo "[✔] Installing ...";
echo "";
git clone https://github.com/thehackingsage/hacktronian.git "$INSTALL_DIR";
echo "#!/bin/bash
python $INSTALL_DIR/hacktronian.py" '${1+"$@"}' > hacktronian;
chmod +x hacktronian;
sudo cp hacktronian /usr/bin/;
rm hacktronian;


if [ -d "$INSTALL_DIR" ] ;
then
    echo "";
    echo "[✔] Tool istalled with success![✔]";
    echo "";
    echo "[✔]====================================================================[✔]";
    echo "[✔] ✔✔✔  All is done!! You can execute tool by typing hacktronian !   ✔✔✔ [✔]";
    echo "[✔]====================================================================[✔]";
    echo "";
else
    echo "[✘] Installation failed![✘] ";
    exit
fi
