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
#include <signal.h>

#define WORKER_PORT 5555

#include "common.h"

void sig_handler(int signum){
  fflush(stdout);
  exit(1);
}

int main(int argc, char *argv[]) {

  signal(SIGPOLL, sig_handler); // Register signal handler

  short worker_port = WORKER_PORT;
  if (argc >= 2)
    worker_port = atoi(argv[1]);

  char message[1024];
  int sock;
  struct sockaddr_in name;
  int bytes;

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
  name.sin_port = htons(worker_port);
  
  if (bind(sock, (struct sockaddr *) &name, sizeof(name))) {
    perror("binding datagram socket");
    exit(1);
  }
  
  printf("Socket has port number %d\n", ntohs(name.sin_port));
  
  struct sockaddr_in client;
  socklen_t clientSize = sizeof(struct sockaddr_in);

  while(1) {
    while ((bytes = recvfrom(sock, message, 1024, 0, (struct sockaddr *) &client, &clientSize)) > 0) {
      sg_msg_t* msg = (sg_msg_t*) message;


      printf("\n\nrecv: '%s' with req ID %d from %d\n", 
        (msg->hdr.msg_type == SCATTER_MSG ? "scatter msg" : "unknown"), msg->hdr.req_id, ntohs(client.sin_port));

      /* Send the message in buf to the server */

      sg_msg_t resp_msg;
      memset(&resp_msg, 0, sizeof(resp_msg));
      resp_msg.hdr.req_id = msg->hdr.req_id;
      resp_msg.hdr.msg_type = 1;  // GATHER Msg
      resp_msg.hdr.body_len = sizeof(uint32_t);
      
      uint32_t res = htonl(worker_port);
      memmove(resp_msg.body, &res, resp_msg.hdr.body_len);

      if (sendto(sock, &resp_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)&client, clientSize) < 0) {
            perror("sendto()");
            exit(2);
       }
    }
  }

  printf("Shutting down server\n");
  close(sock);
}