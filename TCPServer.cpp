//
// Created by Mario Eberth on 28.10.20.
//

#include "TCPServer.h"

#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init

#define BUFFER_SIZE 1024

TCPServer::TCPServer(int _port) {
    ipPort = _port;
}

void TCPServer::initializeSocket() {
    /**
     * Socket
     */
    int _addressFormat = AF_INET;                                                  //Format Ipv4
    int _socketType = SOCK_STREAM;                                                 //TCP
    int _socketProtocol = 0;                                                       //communication protocol > self check

    serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    /**
     * Bind
     */
    struct sockaddr_in serverAddr;                                                 //creates a sockaddr_in object (in = internet)
    serverAddr.sin_family = AF_INET;                                               //Format Ipv4
    serverAddr.sin_port = ipPort;                                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    serverAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(serverAddr.sin_zero), '\0',8);                                // \0 get copied in the first 8 char character of sin_zero

    /**
     * check if the bind method got a error return value (<0)
     */
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {
        std::cout << "Fehler in der Bind" << std::endl;
        return;
    }

    /**
     * set SocketOptions
     */
    bool bOptVal = true;
    int bOptLen = sizeof(bool);
    if (setsockopt(serverSocket, SOL_SOCKET,SO_REUSEADDR,(char*)&bOptVal,bOptLen) == -1){
        std::cout << "socket Freigabe war nicht möglich" << std::endl;
    }

    /**
     * listen
     */
    int backlock = 20;                                                              //count of connections
    int serverListen = listen(serverSocket, backlock);                              //
}

void TCPServer::startSocket() {
    std::cout << "waiting for connection" << std::endl;

    /**
     * accept
     */
    struct sockaddr_in clientAddr;                                              //creates a sockaddr_in object (in = internet)
    socklen_t clientAddrSize = sizeof(clientAddr);                              //creates a socklen_t variable with the size of clientAddr in it
    char msg[BUFFER_SIZE];
    memset(msg, '\0', sizeof(msg));
    while (strcmp(msg, "shutdown") != 0) {
        /**
         * first while > ServerSocket is running and now we create a commSocket
         * commSocket > socket for each client
         */
        int commSocket = accept(serverSocket, (sockaddr *) &clientAddr,&clientAddrSize);    //creates the commSocket in the serverSocket

        while (strcmp(msg, "exit") != 0 && strcmp(msg, "shutdown") != 0 ) {
            /**
             * receive return val > 0 if no problem
             */
            if (recv(commSocket, msg, BUFFER_SIZE, 0) >0) {                             //check if the recv method got a error return value (<=0) something goes wrong the the receive
                /**
                 * send return val > 0 if no problem
                 */
                std::cout << msg << std::endl;
                char *echo = "Echo: ";
                char sendMsg[BUFFER_SIZE];                                                  //create a ACK message
                strcpy(sendMsg, echo);
                strcat(sendMsg, msg);
                strcat(sendMsg, "\0");
                if (!send(commSocket, sendMsg, strlen(sendMsg), 0) >0) {                   //send the ACK and check if the send method got a error return value (<=0)
                    std::cout << "Error Sending message" << std::endl;
                }
                memset(sendMsg, '\0', sizeof(sendMsg));
            } else {
                std::cout << "Fehler in der Übertragung" << std::endl;
                //return -1;
            }

        } // close first while (commSocket with client)
        if (strcmp(msg, "shutdown") != 0){
            memset(msg, '\0', sizeof(msg));                                      //reset msg
        }
        int closeSocket = close(commSocket);                                        //close the client socket
    } // close second while (serverSocket)
    int closeSocket = close(serverSocket);
}

