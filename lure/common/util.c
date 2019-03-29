#include "util.h"
#include <sys/wait.h>
#include <errno.h>
//#include <openssl/des.h>
#include <arpa/inet.h>




int system_shell(const char *cmd){
    if(!cmd || strlen(cmd) <= 0){
        return -1;
    }

    /**< Before invoking system() function(actually before invoking fork()), set SIGCHLD to SIG_DFL handler��
    and after invoking system(actually after invoking wait()/waitpid()), set SIGCHLD to former handler.
    There may be something wrong with it if we don't do that.
    For example if call signal(SIGCHLD, SIG_IGN) before invoke system(), it will cause 'ECHILD' error,
    because wait()/waitpid() could not find the subprocess. */
    sighandler_t old_handler;
    old_handler = signal(SIGCHLD, SIG_DFL);;
    int status = system(cmd);
    signal(SIGCHLD, old_handler);
    if(status < 0)    {
        printf("cmd: %s\t error: %s", cmd, strerror(errno));
        return -1;
    }

    if(WIFEXITED(status)){
        //get the execute status
        //printf("normal termination, exit status = %d\n", WEXITSTATUS(status));
        return 0;
    }
    else if(WIFSIGNALED(status)){
        //if command was interrupted by signal, get the signal value.
        printf("abnormal termination,signal number =%d\n", WTERMSIG(status));
        return -1;
    }
    else if(WIFSTOPPED(status)){
        //if command was suspended by signal, get the signal value.
        printf("process stopped, signal number =%d\n", WSTOPSIG(status));
        return -1;
    }

    return -1;
}





