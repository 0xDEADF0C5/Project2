#!/usr/bin/python

import time
import ctypes
import socket
import requests
import struct
import math

# setup port and max hops
PORT = 33434
MAXIMUM_HOPS = 30  # this is the default for traceroute itself

# ICMP socket is for sending back ICMP packets and requires a raw socket (SOCK_RAW)
ICMPSock = socket.getprotobyname('icmp')
# This is the probe that uses a UDP socket tied to a Datagram Socket
UDPSock = socket.getprotobyname('udp')


def main(targetFile, resultsFile):
    """
    main function contains the flow of the logic.
    returns a tuple of (target, ttl, rtt).
    """

    resultsArray = []
    results = open(resultsFile, 'w')  # this will get a write-only file to put the results into

    results.write("host,TTL,RTT\n")

    # read each individual target
    for target in targetsInFile(targetFile):
        ttl, rtt = hopsAndRTTToTarget(target)
        resultsArray.append((target, ttl, rtt))
        results.write("%s,%s,%s\n" % (target, ttl, rtt)) # insert the data as strings
    print("Tracing Finished. Results:\n", resultsArray)
    result.close()
    # ends connection


def initSockets(ttl):
    """
    creates sockets (both sending and receiving) and returns them
    """
    # Create the sockets themselves
    sendSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDPSock)
    rcvSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMPSock)

    # Set the options of the sending and receiving sockets
    sendSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    rcvSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    timeout = struct.pack("ll", 5, 0)
    rcvSocket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout) # timeout is five seconds

    return rcvSocket, sendSocket

# reads targets from file and outputs them
def targetsInFile(filename):
    with open(filename) as targetFile:
        targets = targetFile.read().splitlines()  # splits lines at the line boundaries
    return targets


def hopsAndRTTToTarget(destinationHostname):
    """
    Finds the number of hops and the RTT to given destination.
    """
    # destination address and port
    print("Probing '%s'..." % destinationHostname)
    destinationIP = socket.gethostbyname(destinationHostname)

    # RTT is the time to go there and back, TTL is the hop count
    ttl = 1
    rtt = time.time()

    while 1:
        rcvSocket, sendSocket = initSockets(ttl)

        # specify the port and an empty string for the hostname
        rcvSocket.bind(("", PORT))

        # send to the destination host (on the same port)
        sendSocket.sendto(b'', (destinationHostname, PORT))

        # placeholders
        currentIP = None
        currentHostname = None

        try:
            # we only need the address part from recvfrom, not the rest of the data
            packet, currentIP = recv_socket.recvfrom(512)
            currentIP = currentIP[0]

            payload = len(packet[56:])
            ipHeader = struct.unpack('!BBHHHBBH4s4s', packet[0:20])  # B means an unsigned character, H is an unsigned short
            # print(ip_header)

            try:
                # find the hostname when we have the ip address
                currentHostname = socket.gethostbyaddr(currentIP)[0]
            except socket.error:
                # if we can't get the hostname, we just make the hostname the ip we got
                currentHostname = currentIP
        except socket.error as error:
            if str(error) != "[Errno 11]Resource temporarily unavailable":  # this is to let probes keep trying instead of spitting lots of errors
                print(error)
            pass
        finally:
            sendSocket.close()
            recvSocket.close()
            # close connection

        # Print out the servers as they come
        if currentIP is not None:
            currentServer = "%s : %s" % (currentIP, currentHostname)
        else:
            currentServer = "*"
        print("%d \t %s" % (ttl, currentServer))

        # destination is either reached or the maximum hops are hit
        if ttl >= MAXIMUM_HOPS or currentIP == destinationIP:
            rtt = time.time() - rtt
            print("Tracing '%s' finished. TTL: %s, RTT: %dms" % (destinationHostname, ttl, rtt * 1000))

            return ttl, rtt * 1000  # multiply by 1000 to get rtt in milliseconds

        ttl = ttl + 1


# this is like the main method of java, but my actual main method is at the top of the program
if __name__ == "__main__":
    main("targets.txt", "results.csv")
