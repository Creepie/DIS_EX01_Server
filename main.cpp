#include <iostream>
#include <sys/socket.h> // socket, bind, listen, accept
#include <netinet/in.h> // IPPROTO_TCP, sockaddr_in,
// htons/ntohs, INADDR_ANY
#include <unistd.h> // close
#include <arpa/inet.h> // inet_ntop/inet_atop
#include <string.h> // strlen
#include <semaphore.h> // sem_init

#ifndef SOCKETSERVER_H
#define SOCKETSERVER_H
#define BUFFER_SIZE 1024

#define IPPORT (_argv[1])

int main(int _argc, char **_argv) {

    //Socket
    int _addressFormat = AF_INET;                                                  //Format Ipv4
    int _socketType = SOCK_STREAM;                                                 //TCP
    int _socketProtocol = 0;                                                       //communication protocol > self check

    int serverSocket = socket(_addressFormat, _socketType, _socketProtocol);       //creates a server Socket

    //Bind
    struct sockaddr_in serverAddr;                                                 //creates a sockaddr_in object (in = internet)
    serverAddr.sin_family = AF_INET;                                               //Format Ipv4
    serverAddr.sin_port = htons(
            atoi(IPPORT));                                  //get the Port from the IPPORT (htons = host to network short, atoi = argument to integer)
    serverAddr.sin_addr.s_addr = INADDR_ANY;                                       //search automatically the ipAdress
    memset(&(serverAddr.sin_zero), '\0',
           8);                                // \0 get copied in the first 8 char character of sin_zero
    if (bind(serverSocket, (sockaddr *) &serverAddr, sizeof(serverAddr)) <
        0) {      //check if the bind method got a error return value (<0)
        std::cout << "Fehler in der Bind" << std::endl;
        return -1;
    }

    //listen
    int backlock = 20;                                                              //count of connections
    int serverListen = listen(serverSocket, backlock);                              //

    //accept
    struct sockaddr_in clientAddr;                                              //creates a sockaddr_in object (in = internet)
    socklen_t clientAddrSize = sizeof(clientAddr);                              //creates a socklen_t variable with the size of clientAddr in it
    while (true) {
        //commSocket > socket for each client
        int commSocket = accept(serverSocket, (sockaddr *) &clientAddr,
                                &clientAddrSize);    //creates the commSocket in the serverSocket

        char msg[BUFFER_SIZE];
        while (strcmp(msg, "exit") != 0) {
            //receive
            if (recv(commSocket, msg, BUFFER_SIZE, 0) >0) {                             //check if the recv method got a error return value (<=0) something goes wrong the the receive
                //send
                std::cout << msg << std::endl;
                char *sendMsg = "ACK";                                                  //create a ACK message
                if (!send(commSocket, sendMsg, strlen(sendMsg), 0) >
                    0) {                   //send the ACK and check if the send method got a error return value (<=0)
                    std::cout << "Error Sending message" << std::endl;
                }
            } else {
                std::cout << "Fehler in der Übertragung" << std::endl;
                //return -1;
            }
        } // close first while
        memset(msg, '\0', sizeof(msg));                                            //reset msg
        int closeSocket = close(commSocket);                                        //close the client socket

    } // close second while
}

#endif
