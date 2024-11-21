#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 3000
#define HEADER_SIZE 4

int main(int argc, char const *argv[])
{
  /*  Create socket file descriptor.
   *
   *  socket(domain, type, protocol)
   *
   *  domain: specifies communication domain (AF_LOCAL for processes on same host,
   *            AF_INET for processes on different hosts connected with IPV4)
   *  type: tcp (SOCK_STREAM) or udp (SOCK_DGRAM)
   *  protocol: IANA protocol number (see: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
   *              specifies which protocol should be used on the socket.
   */
  int server_fd = socket(AF_INET, SOCK_STREAM, 0);

  /*  Check that a valid (non-negative) file descriptor was returned. */
  if (server_fd < 0)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  printf("%d\n", htons(PORT));

  struct sockaddr_in address = {
      .sin_family = AF_INET,         /* Type of address (IPv4) */
      .sin_addr.s_addr = INADDR_ANY, /* Special Empty IP Address.*/
      .sin_port = htons(PORT),       /* Port Number. */
  };
  int addrlen = sizeof(address);
  struct sockaddr *addr_ptr = (struct sockaddr *)&address;

  /* Forcefully attach socket to port */
  int opt = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
  {
    perror("setsockopt");
    exit(EXIT_FAILURE);
  }

  printf("Binding\n");
  /*  Bind the socket to the address and port number. */
  if (bind(server_fd, addr_ptr, addrlen) < 0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  /*  Set the socket to "passive mode" to wait for the client to approach and
   *  create a connection.
   *
   *  listen(fd, backlog)
   *
   *  backlog: maximum length for which queue of pending connections may grow.
   *            client may receive connection error if queue already full.
   *
   */
  if (listen(server_fd, 3) < 0)
  {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  /*  Extract first connection request from the queue and create a new connected
   *  socket and return the file descriptor of this new socket. A connection
   *  has now been established between the client and server. */
  int connection_fd = accept(server_fd, addr_ptr, (socklen_t *)&addrlen);
  if (connection_fd < 0)
  {
    perror("accept");
    exit(EXIT_FAILURE);
  }

  /* Continuously read and echo data from the client. */
  while (1) {
      // Read the request header, which is a 4 byte integer containing the size
      // of the payload
      char header[HEADER_SIZE] = {0};
      ssize_t bytes_read = read(connection_fd, header, HEADER_SIZE);
      if (bytes_read != HEADER_SIZE) {
          if (bytes_read != 0) {
              perror("read failed (server)");
          }
          break;
      }

      int32_t payload_size = *((int32_t*)header);

      // Allocate a buffer large enough to hold the payload
      char *buffer = malloc(payload_size);
      if (!buffer) {
          perror("malloc failed (server)");
          return -1;
      }
      bytes_read = read(connection_fd, buffer, payload_size);

      if (bytes_read != payload_size) {
          if (bytes_read != 0) {
              perror("read failed (server)");
          }
          break;
      }

      // Echo the received message back to the client
      if (send(connection_fd, buffer, bytes_read, 0) <= 0) {
          perror("send failed (server)");
          break;
      }

      free(buffer);
  }

  /* Close connection between client and server. */
  close(connection_fd);

  /* Close the listening socket so no more connections can be accepted. */
  shutdown(server_fd, SHUT_RDWR);

  return 0;
}