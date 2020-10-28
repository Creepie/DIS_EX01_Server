//
// Created by Mario Eberth on 28.10.20.
//

#include "UDPServer.h"

#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init

#define BUFFER_SIZE 1024

UDPServer::UDPServer(int port) {
    ipPort = port;
}

void UDPServer::initializeSocket() {
    //Socket
    int _addressFormat = AF_INET;                                                  //Format Ipv4
    int _socketType = SOCK_STREAM;                                                 //TCP
    int _socketProtocol = 0;                                                       //communication protocol > self check

    serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    //Bind
    struct sockaddr_in serverAddr;                                                 //creates a sockaddr_in object (in = internet)
    serverAddr.sin_family = AF_INET;                                               //Format Ipv4
    serverAddr.sin_port = ipPort;                                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    serverAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(serverAddr.sin_zero), '\0',8);                                // \0 get copied in the first 8 char character of sin_zero
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {     //check if the bind method got a error return value (<0)
        std::cout << "Fehler in der Bind" << std::endl;
        return;
    }
}

void UDPServer::startSocket() {

}

