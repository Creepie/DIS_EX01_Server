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

/**
 * this method initializes the ServerSocket > after that a Client can communicate with the server
 */
void UDPServer::initializeSocket() {
    /**
     * create the Socket with the ipv4 format,.. parameters
     */
    int _addressFormat = AF_INET;                                                  //Format Ipv4
    int _socketType = SOCK_DGRAM;                                                 //UDP
    int _socketProtocol = 0;                                                       //communication protocol > self check

    serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    /**
     * add params into serverAddr > for the Bind
     */
    struct sockaddr_in serverAddr;                                                 //creates a sockaddr_in object (in = internet)
    serverAddr.sin_family = AF_INET;                                               //Format Ipv4
    serverAddr.sin_port = ipPort;                                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    serverAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(serverAddr.sin_zero), '\0',8);                                // \0 get copied in the first 8 char character of sin_zero
    /**
     * start the bind method
     * check if the bind method got a error return value (<0)
     */
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {     //check if the bind method got a error return value (<0)
        std::cout << "Fehler in der Bind" << std::endl;
        return;
    }
}

/**
 * this method starts the UDP Socket > after that a client can communicate
 * and send an Echo from the client message back to the client
 */
void UDPServer::startSocket() {
    std::cout << "ready for conversation" << std::endl;
    /**
     * recvfrom (save the from data after we got a message)
     */
    sockaddr_in from;
    socklen_t frommSize = sizeof(from);


    char msg[BUFFER_SIZE];
    memset(msg, '\0', sizeof(msg));
    while (strcmp(msg, "shutdown") != 0){
        /**
         * recvfrom (check if the return val >= 0 means no error)
         */
        if (recvfrom(serverSocket, msg, BUFFER_SIZE, 0, (sockaddr*) &from, &frommSize) >=0 ){
            std::cout << msg << std::endl;
            char *echo = "Echo: ";
            char sendMsg[BUFFER_SIZE];                                                  //create a ACK message
            strcpy(sendMsg, echo);
            strcat(sendMsg, msg);
            strcat(sendMsg, "\0");
            int msgSize = strlen(sendMsg) + 1;

            /**
             * save from data into toAddr
             */
            sockaddr_in toAddr;
            toAddr.sin_family = from.sin_family;
            toAddr.sin_port = from.sin_port;
            toAddr.sin_addr.s_addr =  from.sin_addr.s_addr;
            memset(&(toAddr.sin_zero),'\0',0);
            int toSize = sizeof(toAddr);

            /**
             * send Echo and check the return value of the sendTo ( if -1 we had an error)
             */
            if (sendto(serverSocket, sendMsg, msgSize,0,(sockaddr*) &toAddr, toSize) == -1){
                std::cout << "Fehler in der Send" << std::endl;
            }
            if (strcmp(msg, "shutdown") != 0){
                    memset(msg, '\0', sizeof(msg));                                      //reset msg
                }
        }
    } // end while
    if (close(serverSocket) == -1){
        std::cout << "Fehler in der Close" << std::endl;
    }

}

