import base64
import os
import socket
import json
import zlib
import rsa
import datetime

# Sets size for the buffer.
BUFFER_SIZE = 4096


# Uses CRC32 to calculate a checksum for our data to be sent.
# Takes json data in to compare the checksum with the calculated checksum.
# The checksum is performed on the type and content of the json.
def checksum_calculator(passedJsonData):

    # Fetches type and content from the jsonData passed.
    name = passedJsonData.get("type")
    content = passedJsonData.get("content")

    # Sets default if name or content is none.
    if name is None:
        name = ""
    if content is None:
        content = ""

    # Forms checksum sequence.
    checksum_sequence = name + content
    checksum = zlib.crc32(bytes(checksum_sequence, "utf-8"))

    return checksum


# Method to send the data.
def sendData(sock, passedJsonData):

    # Calculates checksum.
    checksum_value = checksum_calculator(passedJsonData)
    # Adds to json.
    passedJsonData['checksum'] = checksum_value

    passedJsonData = json.dumps(passedJsonData)

    # Tries to send packet to recipient.
    sock.sendto(passedJsonData.encode(), UDP_ADDRESS)

    try:
        # When a packet is sent, an ACK packet should be returned to confirm it arrived.
        # If an ACK packet is not received back, a socket error is raised.

        # Receiving data.
        packet, server = sock.recvfrom(BUFFER_SIZE)

        # Loads the received packet into a json object.
        receivedPacket = json.loads(packet)

        # Gets the type of the packet.
        packetType = receivedPacket.get("type")

        # Check to seem if checksums match.
        if receivedPacket.get("checksum") is not None:
            if checksum_calculator(receivedPacket) != int(receivedPacket.get("checksum")):
                print("The checksums do NOT match - packet needs to be resent.")
                raise Exception()
            else:
                print("The checksum on ACK matches.")

        print("Packet Type Received:", packetType)

        # If the ACK packet has been sent back, the recipient received the data correctly.
        print(packetType)
        if packetType == "ack":
            print("An ACK packet has been received.")
        else:
            print("An ACK packet has NOT been received.")
            raise socket.error

    except Exception:
        print("An ACK packet has NOT been received.")
        raise socket.error


# Method to receive data.
def receiveData(sock, expectedPacketType):

    # Tries to receive data from recipient.
    packet, server = sock.recvfrom(BUFFER_SIZE)

    # Loads the received packet into a json object.
    receivedPacket = json.loads(packet)

    # Gets the type of the packet.
    packetType = receivedPacket.get("type")

    # Check to seem if checksums match.
    if receivedPacket.get("checksum") is not None:
        if checksum_calculator(receivedPacket) != int(receivedPacket.get("checksum")):
            print("The checksums do NOT match - packet needs to be resent.")
            raise Exception()
        else:
            print("The checksum matches.")

    print("Packet Type Received: ", packetType)

    # The expected package type should match the one received, if not an exception is raised.
    if packetType != expectedPacketType:
        print("Incorrect packet type received.")
        raise Exception()

    # Gets the public key received from recipient.
    if packetType == "recipient_public_key":
        global recipientKey
        recipientKey = rsa.PublicKey.load_pkcs1(receivedPacket.get("content").encode())
        print(recipientKey)

    # Gets the username of the recipient.
    elif packetType == "recipient_username":
        global recipientName
        recipientName = receivedPacket.get("content")
        decodedUsername = base64.b64decode(recipientName)
        recipientName = rsa.decrypt(decodedUsername, privateKey).decode()

    # Gets the message sent back.
    elif packetType == " message":
        global message
        message = receivedPacket.get("content")
        decodedMessage = base64.b64decode(message)
        message = rsa.decrypt(decodedMessage, privateKey).decode()

        print("\n\nHere's the message received:\n------\n" + message + "\n-----\n\n")

    # Sends back an ACK packet to confirm packet was received.
    ackPacketToSend = {"type": "ack"}

    ackPacketToSend = json.dumps(ackPacketToSend)

    # Sends packet to recipient.
    sock.sendto(ackPacketToSend.encode(), UDP_ADDRESS)


# Generates new RSA public and private keys.
publicKey, privateKey = rsa.newkeys(2048)

# Gets username.
localUser = os.getlogin()

# Defines global variables.
global recipientKey
global recipientName

# Gets list of addresses to send greetings to from user.
recipientList = ""
while recipientList == "":
    recipientList = str(input(
        "Enter list of IP addresses to send greetings to using spaces to separate the addresses:\n"))

# Reformat recipient list to print.
recipientList = recipientList.split(" ")
print(recipientList)

# Takes custom message from user.
customMessage = str(input("Please enter your custom message : "))

# Limits the length of the message.
while len(customMessage.encode()) > 200:
    customMessage = str(input("Message can't exceed 200 bytes.\nPlease enter your custom message : "))

# Tries to send greeting to each IP address entered by the user.
for i in range(len(recipientList)):

    # Creates socket for current IP

    # Change the IP Address to the next in the list.
    UDP_IP_ADDRESS = recipientList[i]

    # Regex to validate IP.
    # validIP = re.match(
    # r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
    # UDP_IP_ADDRESS)

    # If IP is not valid, informs user and moves onto next IP.
    # if not validIP:
    # print("IP " + str(i + 1) + " you entered is not valid")
    # continue

    # Setting port number to be used.
    UDP_PORT_NO = 12000
    # Setting receiver address.
    UDP_ADDRESS = (UDP_IP_ADDRESS, UDP_PORT_NO)
    # Setting timeout to 1 second.
    socket.setdefaulttimeout(1)
    # Setting up socket connection.
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Synchronizing packet for initiating connection.
    print("Initialising connection.")
    packetToSend = {"type": "sync"}

    # Tries to send the json data to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, packetToSend)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except socket.error:
        # If there is a problem with the current socket, another attempt is made to resend the data.
        print("Error with connection - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # Cannot send IP to current IP, informs user, closes socket and moves onto next IP.
        print("Unknown error occurred, moving on to next IP address.\n\n")
        clientSocket.close()
        continue

    # Exchange Public keys between sender and receiver.
    print("Exchanging public keys...")

    # Converts the public key into PEM format as bytes and then decodes it to string.
    pubKeyAsPackets = publicKey.save_pkcs1().decode()

    packetToSend = {"type": "sender_public_key", "content": pubKeyAsPackets}

    # Tries to send the json data to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, packetToSend)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except socket.error:
        # If there is a problem with the current socket, another attempt is made to resend the data.
        print("Error with connection - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # Cannot send IP to current IP, informs user, closes socket and moves onto next IP.
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSocket.close()
        continue

    # Tries to receive the key from receiver.
    # noinspection PyBroadException
    try:
        receiveData(clientSocket, "recipient_public_key")
    except socket.timeout as inst:
        # If the request times out it, another attempt is made to receive the key.
        print("Request timed out - receiving data again.")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "recipient_public_key")

        except Exception:
            # If key cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("Error occurred while receiving data from the current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # If Incorrect packet type is received, another attempt is made to receive the data.
        print("Incorrect packet type received, trying again")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "recipient_public_key")
        except Exception:
            # If key cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSocket.close()
            continue

    # Sending a request for the recipient username.
    print("Requesting recipient username...")

    packetToSend = {"type": "request_username"}

    # Tries to send the request to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, packetToSend)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - retrying to receive data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except socket.error:
        # If there is a problem with the current socket, another attempt is made to resend the data.
        print("Error with connection - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # Cannot send IP to current IP, informs user, closes socket and moves onto next IP.
        print("Unknown error occurred, moving on to next IP address.\n\n")
        clientSocket.close()
        continue

    # Receiving recipient username.
    # noinspection PyBroadException
    try:
        receiveData(clientSocket, "recipient_username")

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to receive the username.
        print("Request timed out - retrying to receive data.")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "recipient_username")

        except Exception:
            # If username cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("Error occurred while receiving data from the current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # If Incorrect packet type is received, another attempt is made to receive the data.
        print("Incorrect packet type received, trying again")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "recipient_username")
        except Exception:
            # If username cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSocket.close()
            continue

    print("Recipient username is: " + recipientName)

    # Sending the greeting message.
    # Checks time for correct greeting of Good Morning, Good Afternoon or Good Evening
    if datetime.time(4, 00, 00) < datetime.datetime.now().time() <= datetime.time(11, 00, 00):
        greeting = "Good Morning "
    elif datetime.time(11, 00, 00) < datetime.datetime.now().time() <= datetime.time(18, 00, 00):
        greeting = "Good Afternoon "
    else:
        greeting = "Good Evening "

    message = "\n-----\n" + greeting + recipientName + ".\n" + customMessage + "\n\nFrom: " + localUser + \
              "\n-----\n"

    print("Sending Message: \n", message + "\n")

    # Encrypts message.
    message = rsa.encrypt(message.encode(), recipientKey)
    message = base64.b64encode(message)
    message = str(message, "latin-1")

    packetToSend = {"type": "message", "content": message}

    # Tries to send the json greeting to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, packetToSend)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except socket.error:
        # If there is a problem with the current socket, another attempt is made to resend the data.
        print("Error with connection - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToSend)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # Cannot send IP to current IP, informs user, closes socket and moves onto next IP.
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSocket.close()
        continue

    # Receiving recipient message.
    # noinspection PyBroadException
    try:
        receiveData(clientSocket, "message")

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to receive the username.
        # print("Request timed out - retrying to receive data.")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "message")

        except Exception:
            # If username cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("Error occurred while receiving data from the current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # If Incorrect packet type is received, another attempt is made to receive the data.
        print("Incorrect packet type received, trying again")

        # Tries to receive data again.
        # noinspection PyBroadException
        try:
            receiveData(clientSocket, "message")
        except Exception:
            # If username cannot be received from current IP, informs user, closes socket and moves onto next IP.
            print("An Error occurred receiving data from the current IP, moving on to next address\n\n")
            clientSocket.close()
            continue

    # Ending the connection with the current recipient as the greeting has been sent successfully.

    packetToBeSent = {"type": "fin"}

    # Tries to send the request to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, packetToBeSent)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToBeSent)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except socket.error:
        # If there is a problem with the current socket, another attempt is made to resend the data.
        print("Error with connection - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, packetToBeSent)

        except Exception:
            # Connection cannot be made with the current IP, informs user, closes socket and moves onto next IP.
            print("Cannot establish connection with current IP, moving on to next address.\n\n")
            clientSocket.close()
            continue

    except Exception:
        # Cannot send IP to current IP, informs user, closes socket and moves onto next IP.
        print("Unknown error occurred, moving on to next IP address\n\n")
        clientSocket.close()
        continue

    clientSocket.close()

    print("Terminated connection with recipient - " + str(UDP_IP_ADDRESS) + ".")

print("Finished sending greetings.")
