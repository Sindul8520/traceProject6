from socket import *

import os

import sys

import struct

import time

import select

import binascii

ICMP_ECHO_REQUEST = 8

MAX_HOPS = 30

TIMEOUT = 2.0

TRIES = 2


# The packet that we shall send to each router along the path is the ICMP echo

# request packet, which is exactly what we had used in the ICMP ping exercise.

# We shall use the same packet that we built in the Ping exercise


def checksum(str_):
    # In this function we make the checksum of our packet

    str_ = bytearray(str_)

    csum = 0

    countTo = (len(str_) // 2) * 2

    for count in range(0, countTo, 2):
        thisVal = str_[count + 1] * 256 + str_[count]

        csum = csum + thisVal

        csum = csum & 0xffffffff

    if countTo < len(str_):
        csum = csum + str_[-1]

        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)

    csum = csum + (csum >> 16)

    answer = ~csum

    answer = answer & 0xffff

    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


def build_packet():
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our

    # packet to be sent was made, secondly the checksum was appended to the header and

    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.

    myChecksum = 0

    myID = os.getpid() & 0xFFFF

    # Make a dummy header with a 0 checksum.

    # struct -- Interpret strings as packed binary data

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.

    # Append checksum to the header.

    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':

        myChecksum = htons(myChecksum) & 0xffff

        # Convert 16-bit integers from host to network byte order.

    else:

        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, 1)

    packet = header + data

    return packet


def get_route(hostname):
    timeLeft = TIMEOUT

    tracelist1 = []  # This is your list to use when iterating through each trace

    tracelist2 = []  # This is your list to contain all traces

    for ttl in range(1, MAX_HOPS):

        for tries in range(TRIES):

            destAddr = gethostbyname(hostname)

            # Fill in start

            # Make a raw socket named mySocket

            icmp = getprotobyname("icmp")

            mySocket = socket(AF_INET, SOCK_RAW, icmp)

            # Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))

            mySocket.settimeout(TIMEOUT)

            try:

                d = build_packet()

                mySocket.sendto(d, (hostname, 0))

                t = time.time()

                startedSelect = time.time()

                whatReady = select.select([mySocket], [], [], timeLeft)

                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []:  # Timeout

                    tracelist1.append("* * * Request timed out.")

                    # Fill in start

                    # You should add the list above to your all traces list

                    tracelist2.append(tracelist1)

                    # Fill in end

                recvPacket, addr = mySocket.recvfrom(1024)

                timeReceived = time.time()

                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    # print ("*    *    * Request timed out.")

                    tracelist1.append("* * * Request timed out.")

                    # Fill in start

                    # You should add the list above to your all traces list

                    tracelist2.append(tracelist1)

                    # Fill in end

            except timeout:

                continue



            else:

                icmpHeader = recvPacket[20:28]

                request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                # Fill in end

                try:  # try to fetch the hostname

                    # Fill in start

                    tracelist1.append(gethostbyaddr(str(addr[0]))[0])

                    # Fill in end



                except herror:  # if the host does not provide a hostname

                    # Fill in start

                    tracelist1.append("hostname not returnable")

                    # Fill in end

                if request_type == 11:

                    bytes = struct.calcsize("d")

                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]

                    tracelist1.insert(-1, str(int((timeReceived - t) * 1000)) + "ms")

                    tracelist1.insert(-1, addr[0])

                    tracelist2.append(tracelist1)

                    # print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -t)*1000, addr[0]))

                elif request_type == 3:

                    bytes = struct.calcsize("d")

                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]

                    tracelist1.insert(-1, str(int((timeReceived - t) * 1000)) + "ms")

                    tracelist1.insert(-1, addr[0])

                    tracelist2.append(tracelist1)

                    # print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -t)*1000, addr[0]))

                elif request_type == 0:

                    bytes = struct.calcsize("d")

                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]

                    tracelist1.insert(-1, str(int((timeReceived - t) * 1000)) + "ms")

                    tracelist1.insert(-1, addr[0])

                    tracelist2.append(tracelist1)

                    # print (" %d   rtt=%.0f ms %s" % (ttl,(timeReceived -timeSent)*1000, addr[0]))

                    return tracelist2

                else:

                    print("error")

                break

            finally:

                mySocket.close()


get_route('www.google.com')