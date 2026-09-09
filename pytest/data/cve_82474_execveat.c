#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

/*
 * Run /usr/bin/id via execveat(2). Used to verify ptrace intercept mode applies
 * policy checks to execveat, not just execve(2) (CVE-2026-82474).
 */
int
main(void)
{
    const char *path = "/usr/bin/id";
    char *const argv[] = { (char *)"id", NULL };
    char *const envp[] = { NULL };

    if (syscall(__NR_execveat, AT_FDCWD, path, argv, envp, 0) == -1) {
        perror("execveat");
        return 1;
    }
    return 0;
}
