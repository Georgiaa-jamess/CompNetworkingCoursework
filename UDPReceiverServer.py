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
    checksumVal = checksum_calculator(passedJsonData)

    # Appends checksum to the Json data.
    passedJsonData['checksum'] = checksumVal

    # Dumps the packet to be sent into a json object.
    passedJsonData = json.dumps(passedJsonData)

    # Tries to send the json data to the recipient.
    sock.sendto(passedJsonData.encode(), clientAddress)

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

    # If the ACK packet has been sent back, the recipient received the data correctly.
    print(packetType)
    if packetType == "ack":
        print("An ACK packet has been received.")
    else:
        print("An ACK packet has NOT been received.")
        raise socket.error


# Method to receive data.
def receiveData(sock, expectedPacketType):

    # Tries to receive data from recipient
    packet, address = sock.recvfrom(BUFFER_SIZE)

    # Setting the client address.
    global clientAddress

    clientAddress = address

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

    print("Packet Type Received: ", packetType)

    # The expected package type should match the one received, if not an exception is raised.
    #if packetType != expectedPacketType:
        #print("Incorrect packet type received.")
        #raise Exception()

    if packetType == "sync":
        # Initiating connection with client.
        print("Connection initialized with: ", clientAddress, ".")

    elif packetType == "sender_public_key":
        # Getting the public key received from client.

        global senderKey
        senderKey = rsa.PublicKey.load_pkcs1(receivedPacket.get("content"))

    elif packetType == "message":
        # Decrypts message received.
        message = receivedPacket.get("content")
        decodedMessage = base64.b64decode(message)
        message = rsa.decrypt(decodedMessage, privateKey).decode()

        censoredMessage = profanity.censor(message)
        print(censoredMessage)

    elif packetType == "fin":
        # Terminating connection with client.
        print("Terminating connection.")

    # Sends back an ACK packet to confirm packet was received.
    ackJsonData = {"type": "ack"}

    # Calculates checksum. Includes it in jobject
    checksum_value = checksum_calculator(ackJsonData)

    # adding checksum to json
    ackJsonData['checksum'] = checksum_value

    ackJsonData = json.dumps(ackJsonData)

    # Sends packet to client.
    sock.sendto(ackJsonData.encode(), clientAddress)


localUsername = "Georgia J"

# Generates a new RSA public and private key.
publicKey, privateKey = rsa.newkeys(2048)

# Setting up socket connection.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Sets IP and Port.
serverSocket.bind(('127.0.0.1', 12000))

# Client that's sending messages currently.
global client

print("Started receiver server...")

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
    try:
        receiveData(serverSocket, "sender_public_key")
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Sending UDPReceiverServer encryption public key in PEM format as bytes.
    publicKeyAsPackets = publicKey.save_pkcs1().decode()

    # Assigns json objects to be sent.
    packetToSend = {"type": "recipient_public_key", "content": publicKeyAsPackets}

    # noinspection PyBroadException
    try:
        sendData(serverSocket, packetToSend)
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Username was requested.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "request_username")
    except KeyboardInterrupt:
        break
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
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Received message.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "message")
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Sending custom message.
    message = "\n\nThank you for your message!\n\n"

    # Encrypts message to be sent.
    message = rsa.encrypt(message.encode(), senderKey)
    encryptedMessage = base64.b64encode(message)
    encryptedMessage = str(encryptedMessage, "latin-1")

    # Assigns json objects to be sent.
    packetToSend = {"type": "message", "content": encryptedMessage}

    # noinspection PyBroadException
    try:
        sendData(serverSocket, packetToSend)
    except KeyboardInterrupt:
        break
    except Exception:
        continue

    # Ending communication with server.
    # noinspection PyBroadException
    try:
        receiveData(serverSocket, "fin")
    except KeyboardInterrupt:
        break
    except Exception:
        print("Closed connection with Client.")
        continue

# Closing socket.
serverSocket.close()
