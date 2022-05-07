import base64
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

    # Tries to send the json data to the recipient.
    sock.sendto(jsonData.encode(), clientAddress)

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

    # Tries to receive data from recipient
    jsonData, address = sock.recvfrom(BUFFER_SIZE)

    # Setting the client address.
    global clientAddress
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

    # Gets the type of the packet.
    packetType = x.get("type")

    print("Packet Type Received: ", packetType)

    # The expected package type should match the one received, if not an exception is raised.
    if packetType != expectedPacketType:
        print("Incorrect packet type received.")
        raise Exception()

    if packetType == "sync":
        # Initiating connection with client.
        print("Connection initialized with: ", clientAddress , ".")

    elif packetType == "sender_public_key":
        # Getting the public key received from client.

        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(x.get("content"))


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
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Receiving public key for encryption.
    # noinspection PyBroadException
    receiveData(serverSocket, "sender_public_key")

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
    encryptedUsername = rsa.encrypt(localUsername.encode(), senderKey)
    encryptedUsername = base64.b64encode(encryptedUsername)
    encryptedUsername = str(encryptedUsername, "latin-1")

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

    message = rsa.encrypt(message.encode(), senderKey)
    encryptedMessage = base64.b64encode(encryptedMessage)
    encryptedMessage = str(encryptedMessage, "latin-1")

    # Assigns json objects to be sent.
    packetToSend = {"type": "message", "content": encryptedMessage}

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
        serverSocket.close()
        print("Closed connection with Client.")
        continue
