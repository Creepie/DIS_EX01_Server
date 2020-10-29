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
    int _socketType = SOCK_DGRAM;                                                 //UDP
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
    //recvfrom
    sockaddr_in from;
    socklen_t frommSize = sizeof(from);


    char msg[BUFFER_SIZE];
    while (strcmp(msg, "shutdown") != 0){
        //recvfrom and send Echo
        if (recvfrom(serverSocket, msg, BUFFER_SIZE, 0, (sockaddr*) &from, &frommSize) >=0 ){
            std::cout << msg << std::endl;
            char *echo = "Echo: ";
            char sendMsg[BUFFER_SIZE];                                                  //create a ACK message
            strcpy(sendMsg, echo);
            strcat(sendMsg, msg);
            strcat(sendMsg, "\0");
            int msgSize = strlen(sendMsg) + 1;

            //send
            sockaddr_in toAddr;
            toAddr.sin_family = from.sin_family;
            toAddr.sin_port = from.sin_port;
            toAddr.sin_addr.s_addr =  from.sin_addr.s_addr;
            memset(&(toAddr.sin_zero),'\0',0);
            int toSize = sizeof(toAddr);

            if (sendto(serverSocket, sendMsg, msgSize,0,(sockaddr*) &toAddr, toSize) == -1){
                std::cout << "Fehler in der Send" << std::endl;
            }
            if (strcmp(msg, "shutdown") != 0){
                    memset(msg, '\0', sizeof(msg));                                      //reset msg
                }
        }
    }
    if (close(serverSocket) == -1){
        std::cout << "Fehler in der Close" << std::endl;
    }

}

