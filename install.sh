#!/bin/bash
clear
echo "
   __ __         __   __                _         
  / // /__ _____/ /__/ /________  ___  (_)__ ____ 
 / _  / _ `/ __/  '_/ __/ __/ _ \/ _ \/ / _ `/ _ \
/_//_/\_,_/\__/_/\_\\__/_/  \___/_//_/_/\_,_/_//_/
                                                  
~ Tools for Hacking by Mr. SAGE
";

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
