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


typedef struct __attribute__((packed)) {
    unsigned int    req_id;         // The request ID
    unsigned int    body_len;       // The length of the body in bytes
    unsigned char   msg_type;       // The message type (SCATTER or GATHER)
    unsigned char   flags;          // Extra flags
    char            body[256];      // The body data, up to 256 bytes
} sg_msg_t;


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


    printf("recv: '%s' with req ID %d from %d\n", msg->body, msg->req_id, ntohs(client.sin_port));

    /* Send the message in buf to the server */

    // Send response to COORDINATOR_IP:COORDINATOR_PORT
    // TODO the port should be the corresponding port on the coordinator dedicated to this worker

    // Assume writes and reads are full (no partial processing)
    sg_msg_t resp_msg;
    memset(&resp_msg, 0, sizeof(resp_msg));
    resp_msg.req_id = msg->req_id;
    resp_msg.msg_type = 1;  // GATHER Msg
    resp_msg.body_len = sizeof(uint32_t);
    
    uint32_t res = htonl(worker_port);
    memmove(resp_msg.body, &res, resp_msg.body_len);

    printf("Sending my port back\n");
    if (sendto(sock, &resp_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)&client, clientSize) < 0) {
        perror("sendto()");
        exit(2);
    }

  }

  close(sock);
}