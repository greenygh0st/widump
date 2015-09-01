#!/usr/bin/env python

#Maybe look into using this later??
#http://stackoverflow.com/questions/21613091/how-to-use-scapy-to-determine-wireless-encryption-type
from scapy.all import *
import msvcrt
import cli
import signal

#Proto class
class Proto:
	pass

#create a structure to dump misc data that needs to persist across functions
stores = Proto()
stores.ap_list = []

#catch that control+c (SIGINT) input so we can exit gracefully
#Do this yourself: http://stackoverflow.com/questions/1112343/how-do-i-capture-sigint-in-python :D
def siginit_handler(signal, frame):
        print "One moment while we exit..."
        if stores.args.verbose: print('You pressed Ctrl+C. Gracefully exiting the program.')
        #get rid of the monitor interface
        DestoryMonitorInterface()
        #exit
        print "Exiting..."
        sys.exit(0)

#register the signal interupt handler
signal.signal(signal.SIGINT, siginit_handler)

#check to make sure the following dependencies are present. This should essentially echo the build.py
def check_dependencies():
	#CHECK FOR DEPENDENCIES
	if len(cli.check_sysfile('scapy'))==0:
		print 'scapy executable not found. Make sure you have installed scapy (pip install scapy) or this wont work.'
		return False
	else:
		return True

#could this be a simplier function? Probably...but then it wouldn't be as fun. :)
def ValidInterface():
	avail = False
	wlan = stores.args.interface
	if stores.args.verbose: print 'Looking for: ' + wlan
	if stores.args.alreadymon and not "mon" in wlan:
		print 'You must select a monitor interface (ie. mon0, mon1, etc/whatever) if you are are going to use -m as an option.'
		return
	if stores.args.verbose: print 'Verifying wireless interface is available...'
	s=cli.execute_shell('ifconfig | grep ' + wlan)
	lines = s.splitlines()
	if stores.args.verbose: print lines

	for line in lines:
		if wlan in line:
			avail = True

	if avail:
		if stores.args.verbose: print 'Interface found.'
		return True
	else:
		if stores.args.verbose: print 'Looking a little deeper for that interface you asked for.'
		s2=cli.execute_shell('ifconfig -a | grep ' + wlan)
		lines = s.splitlines()
		if stores.args.verbose: print lines
		for line in lines:
			if wlan in line:
				if stores.args.verbose: print 'Interface was found...but its not up. You need to fix that...or heck we can...'
                cli.execute_shell('ifconfig '+wlan+' up')

		if stores.args.verbose: print 'Interface NOT found anywhere.'
		return False

#interface gets transformed from wlan0 to wlan0.mon
def CreateMonitorInterface():
    #create the name for our eventual monitor interface
    stores.wlanMonName=str(stores.args.interface)+".mon"

    #Shut down the interface so we can make some changes
    if stores.args.verbose: print "Bringing down the "+str(stores.args.interface)+" like you asked."
    cli.execute_shell("ifconfig "+str(stores.args.interface)+" down")

    #Rename the interface -- ip link set peth0 name eth0
    if stores.args.verbose: print "Trying to rename the "+str(stores.args.interface)+" to "+wlanMonName
    cli.execute_shell("ip link set "+str(stores.args.interface)+" name "+wlanMonName)

    #Change the interface into a monitor interface
    if stores.args.verbose: print "Switching the "+wlanMonName+" to being a monitor interface."
    cli.execute_shell("iwconfig "+wlanMonName+" mode monitor")

    #Bring the interface
    #ifconfig <interface> up
    if stores.args.verbose: print "Raising the "+wlanMonName+" like you asked."
    cli.execute_shell("ifconfig "+wlanMonName+" up")
    return wlanMonName

#restore the original interface
def DestoryMonitorInterface():
    if stores.args.verbose: print "One moment...getting rid of the monitor interface that we made."
    #Shut down the interface so we can make some changes
    if stores.args.verbose: print "Bringing down the "+stores.wlanMonName+" like you asked."
    cli.execute_shell("ifconfig "+stores.wlanMonName+" down")

    #Rename the interface -- ip link set peth0 name eth0
    if stores.args.verbose: print "Trying to rename the "+stores.wlanMonName+" to "+str(stores.args.interface)
    cli.execute_shell("ip link set "+stores.wlanMonName+" name "+str(stores.args.interface)

    #Change the interface into a monitor interface
    if stores.args.verbose: print "Switching the "+str(stores.args.interface)+" back to being a managed interface."
    cli.execute_shell("iwconfig "+str(stores.args.interface)+" mode managed")

    #Bring the interface
    #ifconfig <interface> up
    if stores.args.verbose: print "Raising the "+str(stores.args.interface)+" like you asked."
    cli.execute_shell("ifconfig "+str(stores.args.interface)+" up")

    return True

#main loop handler
#the actual handler for scapy that we loop through
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in stores.ap_list:
    				ap_list.append(pkt.addr2)
    				print "AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)

#main loop. This is where the application goes to
def main(args):
    #store our arguments so every function can access them
    stores.args = args
    #check deps
	if not check_dependencies():
		print 'Dependency check failed. Please make sure you have all dependencies installed.'
		return

	#check to make sure that the selected interface is valid
	if not ValidInterface():
		print 'The interface you selected is not valid or does not exist.'
		return

    #create the monitor interface
    monint=""
    if stores.args.alreadymon: #if its already a monitor interface...? Maybe it would be better to determine this progamatically?
        monint=stores.args.interface
    else:
        monint=CreateMonitorInterface()

    #start sniffing
    if len(monint) > 0:
        sniff(iface=str(monint), prn = PacketHandler)
    else:
        print 'Error: Could not create monitor interface.'
