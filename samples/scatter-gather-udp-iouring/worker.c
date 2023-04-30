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
// #define COORDINATOR_PORT 9223

#include "common.h"

int main(int argc, char *argv[]) {

  short worker_port = WORKER_PORT;
  if (argc >= 2)
    worker_port = atoi(argv[1]);

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
  name.sin_port = htons(worker_port);
  
  if (bind(sock, (struct sockaddr *) &name, sizeof(name))) {
    perror("binding datagram socket");
    exit(1);
  }
  
  printf("Socket has port number %d\n", ntohs(name.sin_port));
  
  // struct sockaddr_in server;
  // /* Set up the server name */
  // server.sin_family      = AF_INET;            
  // server.sin_port        = htons(COORDINATOR_PORT);
  // server.sin_addr.s_addr = inet_addr("127.0.0.1");

  struct sockaddr_in client;
  socklen_t clientSize = sizeof(struct sockaddr_in);

  // if(recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr *) &client,
  //           &client_address_size) <0)

  while ((bytes = recvfrom(sock, message, 1024, 0, (struct sockaddr *) &client, &clientSize)) > 0) {
    sg_msg_t* msg = (sg_msg_t*) message;


    printf("\n\nrecv: '%s' with req ID %d from %d\n", 
      (msg->hdr.msg_type == SCATTER_MSG ? "scatter msg" : "unknown"), msg->hdr.req_id, ntohs(client.sin_port));

    /* Send the message in buf to the server */

    // Multi-packet scalar aggregation
    // sg_msg_t resp_msg;
    // memset(&resp_msg, 0, sizeof(resp_msg));
    // resp_msg.hdr.req_id = msg->hdr.req_id;
    // resp_msg.hdr.num_pks = 10;
    // resp_msg.hdr.msg_type = 1;  // GATHER Msg
    // resp_msg.hdr.body_len = sizeof(uint32_t);
    
    // uint32_t res = htonl(worker_port);
    // memmove(resp_msg.body, &res, resp_msg.hdr.body_len);

    // for (int i = 1; i <= 10; i++) {
    //   resp_msg.hdr.seq_num = i;
    //   if (sendto(sock, &resp_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)&client, clientSize) < 0) {
    //       perror("sendto()");
    //       exit(2);
    //   }
    //   printf("sent pack %d\n", resp_msg.hdr.seq_num);
    // }


    // sleep(2);

    // Vector example: send vector of increasing numbers
    sg_msg_t resp_msg;
    memset(&resp_msg, 0, sizeof(resp_msg));
    resp_msg.hdr.req_id = msg->hdr.req_id;
    resp_msg.hdr.msg_type = 1;  // GATHER Msg
    resp_msg.hdr.body_len = sizeof(uint32_t) * RESP_MAX_VECTOR_SIZE;
    
    uint32_t vec[RESP_MAX_VECTOR_SIZE];
    for (int i = 0; i < RESP_MAX_VECTOR_SIZE; i++) {
        vec[i] = i+1;
    }
    memmove(resp_msg.body, vec, resp_msg.hdr.body_len);
    if (sendto(sock, &resp_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)&client, clientSize) < 0) {
        perror("sendto()");
        exit(2);
    }
  }

  close(sock);
}