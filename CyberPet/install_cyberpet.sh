#!/bin/bash
# install_cyberpet.sh
# Geautomatiseerde installatie voor CyberPet zonder audio

echo "CyberPet installatie gestart..."

# Update systeem
sudo apt update && sudo apt upgrade -y

# Installeer essentiële tools
sudo apt install -y python3 python3-pip python3-venv nmap git libatlas-base-dev aircrack-ng hashcat
sudo apt install -y build-essential libpcap-dev libusb-1.0-0-dev iw wireless-tools
sudo apt install -y bluetooth libbluetooth-dev metasploit-framework

# Installeer Bettercap
sudo pip3 install bettercap

# Installeer Inky voor Waveshare V4 e-Ink display
sudo pip3 install inky[rpi]

# Installeer Python-afhankelijkheden
sudo pip3 install flask numpy matplotlib reportlab tensorflow==2.15.0 pybluez

# Maak virtuele omgeving
python3 -m venv /home/pi/cyberpet/venv
source /home/pi/cyberpet/venv/bin/activate

# Installeer Python-afhankelijkheden
pip3 install -r /home/pi/cyberpet/requirements.txt

# Maak directories
mkdir -p /home/pi/cyberpet/{templates,data/logs,data/reports,data/drivers/{realtek,mediatek,atheros},viking_assets}

# Download voorbeeld Viking-assets (vervang door eigen PNG's)
touch /home/pi/cyberpet/viking_assets/placeholder.txt

# Detecteer en installeer USB WiFi-adapter drivers
echo "Detecteren en installeren van USB WiFi-adapter drivers..."
lsusb | grep -E "Realtek|MediaTek|Atheros" > /tmp/usb_wifi_devices.txt

# Realtek chipsets (bijv. RTL8188, RTL8192, RTL8812)
if grep -q "Realtek" /tmp/usb_wifi_devices.txt; then
    echo "Realtek WiFi-adapter gedetecteerd, installeer drivers..."
    git clone https://github.com/aircrack-ng/rtl8188eus /home/pi/cyberpet/data/drivers/realtek/rtl8188eus
    cd /home/pi/cyberpet/data/drivers/realtek/rtl8188eus
    make && sudo make install
    git clone https://github.com/lwfinger/rtw88 /home/pi/cyberpet/data/drivers/realtek/rtw88
    cd /home/pi/cyberpet/data/drivers/realtek/rtw88
    make && sudo make install
fi

# MediaTek chipsets (bijv. MT7921, MT7612)
if grep -q "MediaTek" /tmp/usb_wifi_devices.txt; then
    echo "MediaTek WiFi-adapter gedetecteerd, installeer drivers..."
    git clone https://github.com/morrownr/USB-WiFi /home/pi/cyberpet/data/drivers/mediatek/USB-WiFi
    cd /home/pi/cyberpet/data/drivers/mediatek/USB-WiFi
    ./install_driver.sh
fi

# Atheros chipsets (bijv. AR9271)
if grep -q "Atheros" /tmp/usb_wifi_devices.txt; then
    echo "Atheros WiFi-adapter gedetecteerd, installeer drivers..."
    sudo apt install -y firmware-atheros
fi

# Configureer WiFi-monitor-modus
for iface in $(iw dev | grep Interface | awk '{print $2}'); do
    sudo iw dev $iface set type monitor
    sudo ifconfig $iface up
done

# Configureer Bluetooth
sudo systemctl enable bluetooth
sudo hciconfig hci0 up

# Stel rechten in
sudo chown -R pi:pi /home/pi/cyberpet
sudo chmod +x /home/pi/cyberpet/cyberpet.py

# Download eenvoudige CVE-database (placeholder)
wget -O /home/pi/cyberpet/data/cve_database.json https://example.com/cve_database.json || echo "{}" > /home/pi/cyberpet/data/cve_database.json

# Start CyberPet automatisch bij opstarten
echo "@reboot pi /home/pi/cyberpet/venv/bin/python /home/pi/cyberpet/cyberpet.py" >> /home/pi/.config/crontab

echo "Installatie voltooid! Start CyberPet met: sudo python3 /home/pi/cyberpet/cyberpet.py"