#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

void term_handler(int sig) {
    
}

int main(int argc, char *argv[]) {
    int stdin = open("/dev/tty0", O_RDONLY | O_NOCTTY);
	int stdout = open("/dev/tty0", O_WRONLY | O_NOCTTY);
	int stderr = open("/dev/tty0", O_WRONLY | O_NOCTTY);

    struct sigaction new_act, old_act;

    new_act.sa_handler = term_handler;
    sigemptyset(&new_act.sa_mask);
    sigaddset(&new_act.sa_mask, SIGCHLD);
    new_act.sa_flags = 0;

    sigaction(SIGCHLD, NULL, &old_act);
    if (old_act.sa_handler != SIG_IGN) {
        sigaction(SIGCHLD, &new_act, NULL);
    }

    const char *string = "Sleeping\n";
    int pid = 1;
    if (pid != 0) {
        while (1) {
            write(stdout, string, strlen(string));
            sleep(1);
        }
    }
}