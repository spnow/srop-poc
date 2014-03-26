#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <alloca.h>
#include <sys/mman.h>
#include <sys/types.h>

void ret_15(void) {
  asm(".intel_syntax noprefix\n");
  asm("mov eax, 0x77\n");
  asm("int 0x80\n");
  asm("ret\n");
}

int tcp_listen(int port) {
  int sock;
  struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr = INADDR_ANY };
  sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

  if (sock < 0) {
    fprintf(stderr, "cannot create socket");
    exit(-1);
  }

  int optval = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "cannot bind socket");
    exit(-1);
  }
  if (listen(sock, 5) < 0) {
    fprintf(stderr, "cannot listen");
    exit(-1);
  }

  return sock;
}

int read_input(int conn_fd) {
  char buffer[512];
  uint32_t buffer_address = (uint32_t)&buffer;
  write(conn_fd, &buffer_address, 4);
  printf("[+] Address of buffer = %p\n", buffer);
  char *page = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANON|MAP_SHARED, -1, 0);
  printf("[+] Address of mapped page = %p\n", page);
  write(conn_fd, &page, 4);
  read(conn_fd, buffer, 600);
  return 0;
}

int main(int argc, char const *argv[])
{
	if ( argc < 2 ) {
		printf("Usage: %s <port>", argv[0]);
		exit(-1);
	}

  int listen_fd = tcp_listen(atoi(argv[1]));
  int conn_fd = accept(listen_fd, NULL, NULL);
  if ( conn_fd == -1 ) {
    fprintf(stderr, "Error accepting connection");
    exit(-1);
  }
  close(listen_fd);
  read_input(conn_fd);
  close(conn_fd);

	return 0;
}
