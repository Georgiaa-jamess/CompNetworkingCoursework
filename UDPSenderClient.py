<<<<<<< HEAD
import json
import socket
import zlib

import rsa

# Sets size for the buffer.
from better_profanity import profanity

BUFFER_SIZE = 4096


# Uses CRC32 to calculate a checksum for our data to be sent.
# Takes json data in to compare the checksum with the calculated checksum.
# The checksum is performed on the type and content of the json.
def checksum_calculator(jsonData):

    # Fetches type and content from the jsonData passed.
    name = jsonData.get("type")
    content = jsonData.get("content")

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
def sendData(sock, jsonData):

    # Calculates checksum.
    checksumVal = checksum_calculator(jsonData)

    # Appends checksum to the Json data.
    jsonData['checksum'] = checksumVal
    print(jsonData)

    # Dumps the packet to be sent into a json object.
    jsonData = json.dumps(jsonData)

    # Sets global client variable.
    global client

    # Tries to send the json data to the recipient.
    sock.sendto(jsonData.encode(), client)
=======
import socket
import getpass
import json
import rsa
import datetime
import re


# Sets size for the buffer.
BUFFER_SIZE = 4096

# Global variables.
global recipientKey
global recipientUsername

# Gets username.
localUsername = getpass.getuser()

# Generates new RSA public and private keys.
publicKey, privateKey = rsa.newkeys(2048)


# Method to send the data.
def sendData(sock, passedJsonData):
    # Tries to send packet to recipient.
    sock.sendto(passedJsonData.encode(), UDP_ADDRESS)
>>>>>>> 81ffe81 (Initial Commit)

    try:
        # When a packet is sent, an ACK packet should be returned to confirm it arrived.
        # If an ACK packet is not received back, a socket error is raised.

        # Receiving data.
        packet, server = sock.recvfrom(BUFFER_SIZE)

        # Loads the received packet into a json object.
        x = json.loads(packet)

        # Gets the type of the packet.
        packetType = x.get("type")

        # If the ACK packet has been sent back, the recipient received the data correctly.
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

<<<<<<< HEAD
    # Tries to receive data from recipient
    jsonData, address = sock.recvfrom(BUFFER_SIZE)

    # Setting the client address.
    clientAddress = address

    # Loads the received packet into a json object.
    x = json.loads(jsonData)

    # Checks if the received packet has a checksum.
    if x.get("checksum") is not None:

        # If checksums do not match, an exception will be raised, informs user of outcome.
        if checksum_calculator(x) != int(x.get("checksum")):
            print("Checksums do NOT match, packet needs to be sent again.")
            raise Exception()
        else:
            print("Checksums match.")
=======
    # Tries to receive data from recipient.
    packet, server = sock.recvfrom(4096)

    # Loads the received packet into a json object.
    x = json.loads(packet)
>>>>>>> 81ffe81 (Initial Commit)

    # Gets the type of the packet.
    packetType = x.get("type")

    print("Packet Type Received: ", packetType)

    # The expected package type should match the one received, if not an exception is raised.
    if packetType != expectedPacketType:
        print("Incorrect packet type received.")
        raise Exception()

<<<<<<< HEAD
    if packetType == "sync":
        # Initiating connection with client.
        print("Connection initialized with: " + clientAddress + ".")

    elif packetType == "sender_public_key":
        # Getting the public key received from client.

        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(x.get("content").encode())

    elif packetType == "message":
        # Decrypts message received.
        uncensoredMessage = rsa.decrypt(x.get("content").encode('latin-1'), privateKey).decode()
        censoredMessage = profanity.censor(uncensoredMessage)
        print(censoredMessage)

    elif packetType == "fin":
        # Terminating connection with client.
        print("Terminating connection.")

    # Sends back an ACK packet to confirm packet was received.
    ackJsonData = {"type": "ack"}

    # Dumps the packet to be sent into a json object.
    ackJsonData = json.dumps(ackJsonData)

    # Sends packet to client.
    sock.sendto(ackJsonData.encode(), clientAddress)


localUsername = "GeoJames"

# Sets global sender key variable.
global senderKey

# Generates a new RSA public and private key.
publicKey, privateKey = rsa.newkeys(2048)

# Setting up socket connection.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Sets IP and Port.
serverSocket.bind(('127.0.0.1', 12000))

# Client that's sending messages currently.
global client

print("Started receiver server.")

while True:

    # Client initialised to be set to null.
    client = ()

    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "sync")
    except Exception:
        continue

    # Receiving public key for encryption.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "sender_public_key")
    except Exception:
        continue

    # Sending UDPReceiverServer encryption public key in PEM format as bytes.
    publicKeyAsPackets = publicKey.save_pkcs1().decode()

    # Assigns json objects to be sent.
    packetToSend = {"type": "recipient_public_key", "content": publicKeyAsPackets}

    # noinspection PyBroadException
    try:
        sendData(serverSocket, packetToSend)
    except Exception:
        continue

    # Username was requested.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "request_username")
    except Exception:
        continue

    # Sends username.
    # RSA algorithm encrypts with latin-1 encoding.
    encryptedUsername = rsa.encrypt(localUsername.encode(), senderKey).decode('latin-1')

    # Assigns json objects to be sent.
    packetToSend = {"type": "recipient_username", "content": encryptedUsername}

    # noinspection PyBroadException
    try:
        sendData(serverSocket, packetToSend)
    except Exception:
        continue

    # Received message.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "message")
    except Exception:
        continue

    # Sending custom message.
    message = "\n\nThank you for your message!\n\n"

    # Encrypts message to be sent.
    message = rsa.encrypt(message.encode(), senderKey).decode('latin-1')

    # Assigns json objects to be sent.
    packetToSend = {"type": "message", "content": message}

    # noinspection PyBroadException
    try:
        sendData(serverSocket, packetToSend)
    except Exception:
        continue

    # Ending communication with server.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "fin")
    except Exception:
        print("Closed connection with Client.")
        continue
=======
    # Gets the public key received from recipient.
    if packetType == "recipient_public_key":
        global recipientKey
        recipientKey = rsa.PublicKey.load_pkcs1(x.get("content").encode())

    # Gets the username of the recipient.
    elif packetType == "recipient_username":
        global recipientUsername
        recipientUsername = rsa.decrypt(x.get("content").encode('latin-1'), privateKey).decode()

    # Gets the message sent back.
    elif packetType == "message":
        print(rsa.decrypt(x.get("content").encode('latin-1'), privateKey).decode())

    # Sends back an ACK packet to confirm packet was received.
    ackPacketToSend = {"type": "ack"}

    # Dumps the packet to be sent into a json object.
    ackJsonData = json.dumps(ackPacketToSend)

    # Sends packet to recipient.
    sock.sendto(ackJsonData.encode(), UDP_ADDRESS)


# Gets list of addresses to send greetings to from user.
recipientList = ""
while recipientList == "":
    recipientList = str(input(
        "Enter list of IP addresses to send greetings to. Use spaces to separate the addresses.\n"))

# Reformat recipient list to print.
recipientList = recipientList.split(" ")
print(recipientList)

# Takes custom message from user.
customMessage = str(input("Please enter your custom message : "))

# Tries to send greeting to each IP address entered by the user.
for i in range(len(recipientList)):

    # Creates socket for current IP

    # Change the IP Address to the next in the list.
    UDP_IP_ADDRESS = recipientList[i]

    # Regex to validate IP.
    validIP = re.match(
        r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        UDP_IP_ADDRESS)

    # If IP is not valid, informs user and moves onto next IP.
    if not validIP:
        print("IP " + str(i + 1) + " you entered is not valid")
        continue

    # Setting port number to be used.
    UDP_PORT_NO = 12000
    # Setting receiver address.
    UDP_ADDRESS = (UDP_IP_ADDRESS, UDP_PORT_NO)
    # Setting timeout to 1 second.
    socket.setdefaulttimeout(1)
    # Setting up socket connection.
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Synchronizing packet for initiating connection.
    print("\n\nInitialising connection")
    packetToSend = {"type": "sync"}

    # Dumps the packet to be sent into a json object.
    jsonData = json.dumps(packetToSend)

    # Tries to send the json data to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, jsonData)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, jsonData)

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
            sendData(clientSocket, jsonData)

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

    # Exchange Public keys between sender and receiver.
    print("Exchanging public keys.")

    # Converts the public key into PEM format as bytes and then decodes it to string.
    pubKeyAsPackets = publicKey.save_pkcs1().decode()

    packetToSend = {"type": "sender_public_key", "content": pubKeyAsPackets}

    # Loads the packet to be sent into a json object.
    jsonData = json.dumps(packetToSend)

    # Tries to send the json data to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, jsonData)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - resending data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, jsonData)

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
            sendData(clientSocket, jsonData)

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
        print("Request timed out - resending data.")

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
    print("Requesting recipient username.")

    packetToSend = {"type": "request_username"}

    # Dumps the packet to be sent into a json object.
    jsonData = json.dumps(packetToSend)

    # Tries to send the request to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, jsonData)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - retrying to receive data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, jsonData)

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
            sendData(clientSocket, jsonData)

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

    print(recipientUsername)

    # Sending the greeting message.
    # Checks time for correct greeting of Good Morning, Good Afternoon or Good Evening
    if datetime.time(4, 00, 00) < datetime.datetime.now().time() <= datetime.time(11, 00, 00):
        greeting = "Good Morning "
    elif datetime.time(11, 00, 00) < datetime.datetime.now().time() <= datetime.time(18, 00, 00):
        greeting = "Good Afternoon "
    else:
        greeting = "Good Evening "

    message = "\n-----\n" + greeting + recipientUsername + ".\n" + customMessage + "\n\nFrom: " + localUsername + \
              "\n-----\n"

    print("Sending Message: \n", message + "\n")

    # Encrypts message.
    message = rsa.encrypt(message.encode(), recipientKey).decode('latin-1')

    # Dumps the packet to be sent into a json object.
    packetToSend = {"type": "message", "content": message}
    jsonData = json.dumps(packetToSend)

    # Tries to send the json greeting to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, jsonData)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - retrying to receive data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, jsonData)

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
            sendData(clientSocket, jsonData)

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

    # Dumps the packet to be sent into a json object.
    jsonData = json.dumps(packetToBeSent)

    # Tries to send the request to the address.
    # noinspection PyBroadException
    try:
        sendData(clientSocket, jsonData)

    except socket.timeout as inst:
        # If the request times out it, another attempt is made to resend the data.
        print("Request timed out - retrying to receive data.")

        # Tries to send the json data to the address again.
        # noinspection PyBroadException
        try:
            sendData(clientSocket, jsonData)

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
            sendData(clientSocket, jsonData)

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
>>>>>>> 81ffe81 (Initial Commit)
