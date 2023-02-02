#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#define WORKER_PORT 5555

int main(int argc, char *argv[]) {
  char message[1024];
  int sock;
  struct sockaddr_in name;
  int bytes;

  printf("Listen activating.\n");

  /* Create socket from which to read */
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("Opening datagram socket");
    exit(1);
  }
  
  /* Bind our local address so that the client can send to us */
  memset(&name, 0, sizeof(name));
  name.sin_family = AF_INET;
  name.sin_addr.s_addr = htonl(0);
  name.sin_port = htons(WORKER_PORT);
  
  if (bind(sock, (struct sockaddr *) &name, sizeof(name))) {
    perror("binding datagram socket");
    exit(1);
  }
  
  printf("Socket has port number %d\n", ntohs(name.sin_port));
  
  while ((bytes = read(sock, message, 1024)) > 0) {
    message[bytes] = '\0';
    printf("recv: %s\n", message);
  }


  // recvfrom not needed because the coordinator port should be known by the workers

  // struct sockaddr_in clientAddr;
  // memset(&clientAddr, 0, sizeof(clientAddr));
  // socklen_t len = sizeof(clientAddr);
  // while ((bytes = recvfrom(sock, message, 1024, MSG_WAITALL, (struct sockaddr *) &clientAddr, &len)) > 0) {
  //   message[bytes] = '\0';
  //   printf("recv: '%s' from client w/ port = %d\n", message, ntohs(clientAddr.sin_port));
  // }

  close(sock);
}