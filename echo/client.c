#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

int main() {
    // First, we need to create a TCP/IP socket 
    int s;
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    // We need to specify the IP address and port number of the server we're
    // connecting to. Later, this is cast into a sockaddr. This lets us properly
    // lay out the address data in a way that the kernel can correctly
    // interpret.
    struct sockaddr_in sa; 
    sa.sin_family = AF_INET;
    sa.sin_port = htons(13);
    sa.sin_addr.s_addr = htonl((((((132 << 8) | 163) << 8) | 97) << 8) | 6);

    // In this case, establish a connection with the server using the three way
    // TCP handshake.
    if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("connect");
        close(s);
        return 2;
    }

    // Now, we can treat the socket like any other file and can therefore read
    // from it to extract the data sent by the time server.
    int bytes;
    char buffer[BUFSIZ+1];
    while ((bytes = read(s, buffer, BUFSIZ)) > 0)
        write(1, buffer, bytes);

    close(s);
    return 0;
}