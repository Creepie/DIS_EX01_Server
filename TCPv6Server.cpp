//
// Created by Mario Eberth on 02.11.20.
//

#include "TCPv6Server.h"

#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init

#define BUFFER_SIZE 1024

/**
 * the Constructor declare _port into the global variable ipPort
 * @param port is the given port from the main
 */
TCPv6Server::TCPv6Server(int port) {
    //ipPort is a global variable which holds the given port
    ipPort = port;
}

/**
 * this method initialize the Server Socket to be ready for the communication with the clients
 */
void TCPv6Server::initializeSocket() {

    /**
     * creates a server Socket with the right param like tcp type and so on
     */
    int _addressFormat = AF_INET6;          //Format Ipv6
    int _socketType = SOCK_STREAM;          //TCP
    int _socketProtocol = 0;                //communication protocol > self check

    serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    /**
     * check if the bind method got a error return value (<0) > if error exit
     * Bind
     */
    struct sockaddr_in6 serverAddr;          //creates a sockaddr_in object (in = internet)
    serverAddr.sin6_family = AF_INET6;       //Format Ipv6
    serverAddr.sin6_flowinfo = 0;
    serverAddr.sin6_port = ipPort;           //get the Port from the ipPort variable
    serverAddr.sin6_scope_id = 0;
    serverAddr.sin6_addr = IN6ADDR_ANY_INIT;

    /**
     * check if the bind method got a error return value (<0)
     */
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <0) {
        std::cout << "Fehler in der Bind" << std::endl;
        exit(-1);
    }

    /**
     * setSocketOptions
     * this method is for optimization
     */
    bool bOptVal = true;
    int bOptLen = sizeof(bool);
    if (setsockopt(serverSocket, SOL_SOCKET,SO_REUSEADDR,(char*)&bOptVal,bOptLen) == -1){
        std::cout << "socket Freigabe war nicht möglich" << std::endl;
    }

    /**
     * listen
     * set the server in listen mode (backlog = the count of connections)
     */
    int backlog = 20;
    if(listen(serverSocket, backlog) < 0){
        std::cout << "got a error in the backlog" << std::endl;
        exit(-1);
    }
} // end initializeSocket method

/**
 * this method starts the socket and waits for clients
 * the server sends an ECHO to the Client
 */
void TCPv6Server::startSocket() {
    std::cout << "waiting for connection" << std::endl;

    /**
     * accept > the server accepts a client
     */
    struct sockaddr_in6 clientAddr;                                              //creates a sockaddr_in object (in = internet)
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
            if (recv(commSocket, msg, BUFFER_SIZE, 0) >0) {                     //check if the recv method got a error return value (<=0) something goes wrong the the receive
                /**
                 * send return val > 0 if no problem
                 */
                std::cout << msg << std::endl;
                char *echo = "Echo: ";
                char sendMsg[BUFFER_SIZE];                                      //create a ACK message
                strcpy(sendMsg, echo);
                strcat(sendMsg, msg);
                strcat(sendMsg, "\0");
                if (!send(commSocket, sendMsg, strlen(sendMsg), 0) >0) {        //send the Echo and check if the send method got a error return value (<=0)
                    std::cout << "Error Sending message" << std::endl;
                }
                memset(sendMsg, '\0', sizeof(sendMsg));
            } else {
                std::cout << "Fehler in der Übertragung" << std::endl;
                return;
            }

        } // close first while (commSocket with client)
        if (strcmp(msg, "shutdown") != 0){
            //reset the msg
            memset(msg, '\0', sizeof(msg));             //reset msg
        }
        close(commSocket);                                 //close the client socket
    } // close second while (serverSocket)
    close(serverSocket);
}