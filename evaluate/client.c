#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define PORT 3000
#define SERVER_ADDR "127.0.0.1"
#define HEADER_SIZE 4
#define BUFFER_SIZE 1024 * 25
#define ITERATIONS 250000

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
  int client_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (client_fd < 0)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,   /* Type of address (IPv4) */
      .sin_port = htons(PORT), /* Port Number. */
  };
  int addrlen = sizeof(serv_addr);
  struct sockaddr *addr_ptr = (struct sockaddr *)&serv_addr;

  /* Convert IPv4/IPv6 addresses from string to binary form */
  if (inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr) <= 0)
  {
    printf("Invalid or unsupported address\n");
    exit(EXIT_FAILURE);
  }

  /* Attempts to connect the client socket to the specified address. */
  if (connect(client_fd, addr_ptr, addrlen) < 0)
  {
    printf("Connection failed\n");
    exit(EXIT_FAILURE);
  }

  // The message contains a header (4 bytes) with the payload size, and the
  // payload itself
  char message[HEADER_SIZE + BUFFER_SIZE];
  int32_t value = BUFFER_SIZE;
  memcpy(message, &value, sizeof(value));
  memset(&message[HEADER_SIZE], '0', BUFFER_SIZE);

  /* Send data to server. */
  double total_time = 0.0;
  for (int i = 0; i < ITERATIONS; i++) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Request
    ssize_t bytes_sent = send(client_fd, message, sizeof(message), 0);
    if (bytes_sent < 0) {
      perror("send failed (client)");
      continue;
    }

    // Response
    char buffer[sizeof(message)] = {0};
    if (read(client_fd, buffer, sizeof(message)) <= 0) {
      perror("read failed (client)");
      continue;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    total_time += time_taken;
  }

  // Each request contains the buffer and the header, where as each response
  // only contains the buffer.
  double total_gbytes = (HEADER_SIZE + BUFFER_SIZE * 2) * (ITERATIONS / 1e9);

  printf("\033[1;35m"); // Set bold and pink (magenta) color
  printf("%-20s %10.2f microseconds\n", "Average RTT:", (total_time / ITERATIONS) * 1e6);
  printf("%-20s %10.2f GB/sec\n", "Throughput:", ((4 / 1e9) * ITERATIONS + ((2 * BUFFER_SIZE) / 1e9) * ITERATIONS) / total_time);
  printf("\033[0m"); // Reset the style (remove bold and color)

  /* Close connection between client and server. */
  close(client_fd);

  return 0;
}