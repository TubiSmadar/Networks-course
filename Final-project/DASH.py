import requests
from socket import *
import os
import time
import errno


RUDP_HEADER = 12
START_CHUNK = 1
STDN_BUFFER = 1024


def sendImagesOverTCP():
    SERVER_ADDRESS = ('', 30577)
    # serverSocket = socket.socket()
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(SERVER_ADDRESS)
    serverSocket.listen(1)
    print("The DASH server is ready for connections.")

    clientSocket, addrClient = serverSocket.accept()
    print("Recieved connection from client ",addrClient)

    message = "Hello from DASH!\nThere are 25 video frames available for this video.\nPlease select the video quality you would like:\n720, 480 or 360\n"
    clientSocket.send(bytes(message.encode()))
    quality = clientSocket.recv(STDN_BUFFER).decode()

    img_dir = os.getcwd()+"/Pictures"
    frameCount = 1

    while(frameCount <= 25):
        start = time.perf_counter()
        imageFile = img_dir+f'/{quality}'+f"/{frameCount}.png"
        with open(imageFile, "rb") as imageFile:
            imageStr = imageFile.read()
        clientSocket.sendall(imageStr)
        clientSocket.send("Finished".encode())
        frameCount += 1
        ack = clientSocket.recv(STDN_BUFFER)
        finish = time.perf_counter()
        new_quality = verifyTCPQuality(start, finish, quality)
        quality = new_quality
    print("Finished sending frames to client.")
    
    time.sleep(3)
    serverSocket.close()


def verifyTCPQuality(start, finish, quality):
    if (finish - start) > 1 :
        if quality == "720":
            quality = "480"
            print("quality changed from 720 to 480")
        elif quality == "480":
            quality = "360"
            print("quality changed from 480 to 360")
    elif (finish - start) < 0.5 :
        if quality == "360":
            quality = "480"
            print("quality changed from 360 to 480")
        elif quality == "480":
            quality = "720"
            print("quality changed from 480 to 720")
    return quality


def sendImagesOverRUDP():
    SERVER_ADDRESS = ('',30577)
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(SERVER_ADDRESS)
    print("The DASH server is ready for connections.")

    buffer, client_address = serverSocket.recvfrom(STDN_BUFFER)
    print("Received request from client:", buffer.decode(), client_address)

    message = "Hello from DASH!\nThere are 25 video frames available for this video.\nPlease select the video quality you would like:\n720, 480 or 360\n"
    serverSocket.sendto(message.encode(), client_address)
    quality, client_address = serverSocket.recvfrom(STDN_BUFFER)
    quality = quality.decode()

    img_dir = os.getcwd() + "/Pictures"
    frameCount = 1

    while frameCount <= 25:
        start = time.perf_counter()
        imageFile = img_dir + f'/{quality}' + f"/{frameCount}.png"
        sendImage(imageFile, frameCount, client_address, serverSocket)
        finish = time.perf_counter()
        new_quality = verifyUDPQuality(start, finish, quality)
        quality = new_quality


        timer = 10
        while timer > 0:
            serverSocket.setblocking(0)
            try:
                message, client_address = serverSocket.recvfrom(STDN_BUFFER)
                if "ACK" in message.decode():
                    frameCount += 1
                    break
            except error:
                if error.errno == errno.EWOULDBLOCK:
                    pass
            serverSocket.setblocking(1)
            timer -= 1

        if timer == 0:
            print(f"Timeout occured while waiting for ACK of frame {frameCount}.\nLowering quality and resending frame.")
            quality = "360"

    print("Finished sending frames to client.")
    time.sleep(3)
    serverSocket.close()


def sendImage(imageFile, frameCount, client_address, serverSocket):
    with open(imageFile, "rb") as img:
        
        # Define the sequence number and expected sequence number
        sequence_number = 0
        CHUNK = START_CHUNK
        
        while True:
            image_data = img.read(CHUNK)
            if not image_data:
                break

            # Construct the data message
            segment = f'Data:{frameCount}:{sequence_number}:{len(image_data)}'.encode() + image_data
            
            # Send the data message
            serverSocket.sendto(segment, client_address)
            print(f"Sent data message to client: Frame {frameCount}, Seq {sequence_number}")

            time.sleep(0.75)

            serverSocket.setblocking(0)
            try:
                message, client_address = serverSocket.recvfrom(STDN_BUFFER)
                nack = message.decode()
                if "NACK" in nack:
                    missing_segment = int(nack[5:])
                    #img.seek(CHUNK*missing_segment, 0)
                    sequence_number = missing_segment
                    CHUNK = max(CHUNK/2, 1)
            except error:
                if error.errno == errno.EWOULDBLOCK:
                    pass
            serverSocket.setblocking(1)
            
            if CHUNK < 32000:
                CHUNK *= 2
            else:
                CHUNK = 63500
            sequence_number += 1

    # Send termination message
    serverSocket.sendto(b"Finished", client_address)


def verifyUDPQuality(start, finish, quality):
    if (finish - start) > 1:
        if quality == "720":
            quality = "480"
            print("quality changed from 720 to 480")
        elif quality == "480":
            quality = "360"
            print("quality changed from 480 to 360")
    elif (finish - start) < 0.5 :
        if quality == "360":
            quality = "480"
            print("quality changed from 360 to 480")
        elif quality == "480":
            quality = "720"
            print("quality changed from 480 to 720")
    return quality


def main():
    sendImagesOverTCP()
    sendImagesOverRUDP()

if __name__ == '__main__':
    main()