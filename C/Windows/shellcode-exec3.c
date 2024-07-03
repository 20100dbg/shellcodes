#include <stdio>
#define SCSIZE 4096
char payload[SCSIZE] = "PAYLOAD:";

int main(int argc, char **argv) {
    (*(void (*)()) payload)();
    return(0);
}
