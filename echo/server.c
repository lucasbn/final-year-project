#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BACKLOG_SIZE 4

int main() {
    // First, we need to create a TCP/IP socket 
    int s;
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    // We then specify that our socket will receive communication requests on
    // port 13 on any IP address assigned to this machine.
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(13);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
        perror("bind");
        return 2;
    }

    // Transition the socket into passive mode so that it can accept incoming
    // communication requests and place them on the backlog
    listen(s, BACKLOG_SIZE);

    for (;;) {
        // Take the first communication request in the backlog, create a new
        // socket associated with file descriptor c.
        socklen_t b = sizeof sa;
        int c;
        if ((c = accept(s, (struct sockaddr *)&sa, &b)) < 0) {
            perror("accept");
            return 4;
        }

        // Associate the file descriptor with the client FILE object so that we
        // can perform actions like read and write on it
        FILE *client;
        if ((client = fdopen(c, "w")) == NULL) {
            perror("fdopen");
            return 5;
        }

        time_t t;
        if ((t = time(NULL)) < 0) {
            perror("time");
            return 6;
        }

        // Write the current datetime stamp to the file
        struct tm *tm = gmtime(&t);
        fprintf(client, "%.4i-%.2i-%.2iT%.2i:%.2i:%.2iZ\n",
            tm->tm_year + 1900,
            tm->tm_mon + 1,
            tm->tm_mday,
            tm->tm_hour,
            tm->tm_min,
            tm->tm_sec
        );

        fclose(client);
    }
}