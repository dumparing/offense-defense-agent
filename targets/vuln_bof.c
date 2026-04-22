/*
 * vuln_bof.c — Vulnerable binary: stack buffer overflow
 *
 * Vulnerability: uses gets() to read into a fixed-size stack buffer.
 *                No bounds checking → attacker can overwrite return address.
 *
 * Compile:  gcc -fno-stack-protector -no-pie -z execstack -o vuln_bof vuln_bof.c
 * Purpose:  CTF-style target for the agent to analyze.
 *
 * AUTHORIZED TESTING ONLY — intentionally vulnerable.
 */

#include <stdio.h>
#include <string.h>

void secret_function(void) {
    printf("ACCESS GRANTED: You reached the secret function!\n");
}

void vulnerable_function(void) {
    char buffer[64];

    printf("Enter your name: ");
    gets(buffer);  /* VULNERABILITY: no bounds checking */

    printf("Hello, %s!\n", buffer);
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);  /* disable buffering so output isn't lost on crash */
    printf("=== Buffer Overflow Demo ===\n");
    printf("Binary: vuln_bof\n");
    printf("Buffer size: 64 bytes\n\n");

    vulnerable_function();

    printf("Program exited normally.\n");
    return 0;
}
