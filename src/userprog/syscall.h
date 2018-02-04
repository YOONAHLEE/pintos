#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/stdbool.h"

void syscall_init (void);
typedef int pid_t;

//밑에꺼 이미 lin/user/syscall.h에 선언되어있음

void halt(void);
void exit(int status);
pid_t exec(const char* cmd_line);
int wait(pid_t pid);
int read(int fd, void* buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size);


int pibonacci(int n);
int sum_of_four_integers(int a,int b,int c,int d);

//for proj2-2
int open(const char* file);
bool create(const char* fle, unsigned initial_size);
bool remove(const char* file);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);



#endif /* userprog/syscall.h */
