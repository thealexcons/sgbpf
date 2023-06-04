#define _GNU_SOURCE
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
#include <errno.h>
#include <pthread.h>
#include <sched.h>

#define WORKER_PORT 5555

#include "common.h"

static int completedReqs = 0;


void sig_handler(int signum){
  printf("num requests served: %d", completedReqs);
  fflush(stdout);
  exit(0);
}


int main(int argc, char *argv[]) {

  signal(SIGPOLL, sig_handler); // Register signal handler

  int cpu = 0;
  short worker_port = WORKER_PORT;
  if (argc >= 3) {
    worker_port = atoi(argv[1]);
    cpu = atoi(argv[2]);
  }

  // char message[1024];
  int sock;
  struct sockaddr_in name;
  int bytes;

  /* Create socket from which to read */
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("Opening datagram socket");
    exit(1);
  }

  // socklen_t s = sizeof(int);
  // int x;
  // if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &x, &s)) {
  //     fprintf(stderr, "Error getsockopt(SO_RCVBUF): %s\n", strerror(errno));
  // } else {
  //     fprintf(stdout, "Recv buf size set to %d\n", x);
  // }

  // int n = sizeof(sg_msg_t) * 4000;  // increase to 4k packets 
  // if (setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &n, sizeof(n)) == -1) {
  //   fprintf(stdout, "Failed on increasing receive buffer");
  //   exit(1);  
  // }

  // int y;
  // if (getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &y, &s)) {
  //     fprintf(stderr, "Error getsockopt(SO_RCVBUF): %s\n", strerror(errno));
  // } else {
  //     fprintf(stdout, "Recv buf size set to %d\n", y);
  // }

  // Pin to the CPU num provided
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(cpu, &cpuset);
  sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

  /* Bind our local address so that the client can send to us */
  memset(&name, 0, sizeof(name));
  name.sin_family = AF_INET;
  name.sin_addr.s_addr = htonl(0);
  name.sin_port = htons(worker_port);
  
  if (bind(sock, (struct sockaddr *) &name, sizeof(name))) {
    perror("binding datagram socket");
    exit(1);
  }
  
  printf("[WORKER %d] started, pinned to CPU %d ------------------\n", worker_port, cpu);

  struct sockaddr_in client;
  socklen_t clientSize = sizeof(struct sockaddr_in);

  char buf[sizeof(sg_msg_t)];
  int totalBytes = 0;
  while(1) {
      bytes = recvfrom(sock, buf, sizeof(sg_msg_t), 0, (struct sockaddr *) &client, &clientSize);
      if (bytes < 0) {
          printf("[WORKER %d] recvfrom() failed. Got return %d and errno = %d\n", 
                          worker_port, bytes, errno);
          fflush(stdout);
          continue;
      }
      totalBytes += bytes;

      sg_msg_t* msg = (sg_msg_t*) buf;
      // printf("[WORKER %d] got req with ID %d (total bytes = %d)\n", worker_port, msg->hdr.req_id, totalBytes);
      // fflush(stdout);
      if (msg->hdr.msg_type == ALL_GATHER_MSG) {
          printf("[WORKER %d] got all gather response for req %d, data vector = \n", worker_port, msg->hdr.req_id);
          for (int i = 0; i < RESP_MAX_VECTOR_SIZE; i++) {
            printf("[WORKER %d]  vec[%d] = %d\n", worker_port, i, ((uint32_t*)msg->body)[i]);
          }
          fflush(stdout);
      }

      // Vector example: send vector of increasing numbers
      sg_msg_t resp_msg;
      memset(&resp_msg, 0, sizeof(resp_msg));
      resp_msg.hdr.req_id = msg->hdr.req_id;
      resp_msg.hdr.msg_type = GATHER_MSG;  // GATHER Msg
      resp_msg.hdr.body_len = sizeof(uint32_t) * RESP_MAX_VECTOR_SIZE;
      
      uint32_t vec[RESP_MAX_VECTOR_SIZE];
      for (int i = 0; i < RESP_MAX_VECTOR_SIZE; i++) {
          vec[i] = i;
      }
      memmove(resp_msg.body, vec, resp_msg.hdr.body_len);
      if (sendto(sock, &resp_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)&client, clientSize) < 0) {
          printf("[WORKER %d] sendto() failed on req ID %d\n", worker_port, msg->hdr.req_id);
          fflush(stdout);
          continue;
      }

      // printf("[WORKER %d] sent response for req with ID %d\n", worker_port, resp_msg.hdr.req_id);
      // fflush(stdout);
      completedReqs++;

      // printf("[WORKER %d] handled reqs: %d\n", worker_port, completedReqs);
      // fflush(stdout);
  }

  fprintf(stdout, "[WORKER %d] shutting down", worker_port);
  close(sock);
}