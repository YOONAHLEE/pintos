#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "process.h"
#include "devices/shutdown.h"
//for file system ( proj 2-2)
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
int try = 1;

struct semaphore mutex;
//struct semaphore write;
/*

struct semaphore{
unsigned value; //current value
struct list waiters;//list of waiting threads
}
void sema_init(struct semaphore* sema, unsigned value)  //value값으로 init

struct lock{
struct thread* holder; //thread holding lock
struct semaphore semaphore; // binary semaphore controlling access
};

void lock_init(struct lock*)
void lock_acquire(struct lock*)
bool lock_try_acquire( struct lock*)
void lock_relelase(struct lock*)
bool lock_held_by_current_thread(const struct lock*)

   */
//bool lock = false; //semaphore을 위해서, lock이 풀려있다. (True->lock 이 걸려있다. 다른 instruction은 critical section에 들어갈수 없다)
//struct semaphore sema_lock; 


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
void halt(void){
		shutdown_power_off();
}
/*exit함수
terminates the current user program, returning status to the kernel
if the process's parent wait for it, this is the status that will be returned.
Conventionally, a status of 0 indicates success and nonzero values indicate errors*/
void exit(int status){


		//char onlyname[40];
		struct thread* current_program;
		current_program = NULL;
		current_program = thread_current();
	//	int index;
		//thread_current : checks that the 'magic' member of the running thread's 'struct thread' is set to THREAD_MAGIC. Stack overflow will normallly change this value, triggering the assertion.
		//return the running thread.
	
		current_program->exit_status = status;
				//printf(" 설마 exit에서 무한루프 도는건가\n");	

		
		if(current_program->parent != NULL)
			current_program->parent->child_exit_status = current_program->exit_status;

        current_program->if_child_finished = -1;


				//printf(" 설마 exit에서 무한루프 도는건가\n");
		
				//current_program->if_child_finished = -1;//child를 기다릴 필요가 없다 ( 0이라면 자식을 기다리는 중) 
		//if the process's parent wait for it, this is the status that will be returned, and then, parent does not have to wait for this child process
		char string[16], *ptr;
		strlcpy(string,current_program->name,16);
		printf("%s: exit(%d)\n",strtok_r(string," ",&ptr), status<0?-1:status);


		if( current_program->parent!= NULL){//child는 죽은것 만약 0이라는것은 기다리는 중
		  current_program->parent->if_child_finished = 1;
  
        }

		//printf( " exit은 잘 끝났어\n");
	//	current_program->exit_status = status;
		thread_exit();//terminate current program //이거 호출하면 여기서 해당하는 thread all_list에서 지워줌

}
pid_t exec( const char* cmd_line){
//runs the executable whose name is given in cmd_line, passing any given arguments, 
// and returns the new process's program id.(프로세스 생성)
// Must return pid -1, which otherwise should not be a valid pid, if the program cannot load or run for any reason.
//Thus, the parent process cannot return from the exec until it know whether the child process successfully loaded its executable.
//YOu must use appropriate "synchronization to ensure this".
//ex) wait(exec("a.out"))




/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

// tid_t process_execute (const char *file_name) 

		return process_execute(cmd_line);


}
int wait(pid_t pid){
//waits for a child process pid and retrieves the child's exit status!
//if pid is still alive, waits until it terminates. Then returns the status that pid passed to exit

//if pid did not call exit(), but was terminated by the kernel (killed due to an exception), wait(pid) must return -1

//wait must fail and return -1 
		// pid does not refer to a direct child of the calling process. pid is a direct child of the calling process if and only if the calling process received pid as a return value from a successful call to exec.
		// Note that children are not inherited: if A spawns child B and B spawns child process C, then A cannot wait for C, even if B is dead. A call to wait(c) by process A must fail. Similarly, orphaned processes are not assigned to a new parent if their parent process exits before they do.
		//The process that calls wait has already called wait on pid. That is,  a process may wait for any given child at most once


//This is implemented in "process_wait()" in process.c
//Thus, just call process_wait()
		return (process_wait(pid));

}
//read함수와 write함수 : FILE DESCRIPTOR, stdin = 0, stdout = 1
//Reads size bytes from the file open as fd into buffer. Returns the number of bytes
//actuallint read(int fd, void* buffer, unsigned size)y read (0 at end of file), or -1 if the file could not be read (due to a condition
//other than end of file). Fd 0 reads from the keyboard using input_getc().
// pintos/src/devices/input.c    uint8_t input_getc(void) 사용

int read(int fd, void* buffer, unsigned size){

		int index;
		struct thread* nowthread;
		struct file* nowfile;
        int error =0;

	
		if (buffer == NULL) return -1;
        if( buffer >= PHYS_BASE ) exit(-1);
		if( buffer  + size > PHYS_BASE)
				exit(-1);

		if(fd ==0){
	
		for(index=0; index<(int)size; index++)
				*(char*)(buffer+index) = input_getc();

		return (uint32_t)size;
		}
        else if(fd == 1)
          exit(-1);

		nowthread = thread_current();
		if(nowthread != NULL){		
				if( (nowthread->fileList[fd])!= NULL){
					nowfile = (struct file*)(nowthread->fileList[fd]);
					if(error!=0){return -1;}
                    index = (int)file_read(nowfile,buffer,size);
					return (uint32_t)index;
				}
				else
					return -1;
		}
		else 
				return -1;

		return -1;
}

/*
Writes size bytes from buffer to the open file fd. 
Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
Writing past end-of-file would normally extend the file, but file growth is not implemented
by the bcasic file system. The expected behavior is to write as many bytes as
possible up to end-of-file and return the actual number written, or 0 if no bytes could
be written at all.
Fd 1 writes to the console. Your code to write to the console should write all of buffer
in one call to putbuf(), at least as long as size is not bigger than a few hundred
bytes. (It is reasonable to break up larger buffers.) Otherwise, lines of text output
by different processes may end up interleaved on the console, confusing both human
readers and our grading scripts.

pintos/src/lib/kernel/console.c   void putbuf()함수 이용

*/

int write(int fd, const void* buffer, unsigned size){

		off_t numbytes; // file_write : returns the number oof bytes actually written,
		//int index;
        int error = 0;
		if(buffer == NULL)
				return -1;
        else
          error = 0;

		if(!is_user_vaddr(buffer+size-1))
          exit(-1);
        else error =0;
		if(buffer >= PHYS_BASE) exit(-1);
        else error = 0;
        if(fd ==0)
          exit(-1);
		else if(fd!=1){ //proj 2-2 에서 새로 추가한 내용

				struct thread* nowthread;
				struct file* nowfile;
				nowthread = thread_current();
				if(nowthread != NULL){

						if( (nowthread->fileList[fd])!= NULL){

								if( (finding2_withname(nowthread->openfilename[fd]))!= NULL){
										//printf("finding2_withname 이 문제인가보오\n");
										return 0;
								}
								else{ 
									nowfile = (struct file*)(nowthread->fileList[fd]);
									
              
                                    if(error!=0){
                                        printf("write- 오류가 있다 \n");
                                        return -1;
                                    }
                                        
                                    numbytes = file_write(nowfile,buffer,size);
									return (uint32_t)numbytes;
									
								}
						}
						else
								return -1;
				}
				else return -1;
		}
		else{
              
				putbuf(buffer,size);
				return (uint32_t)size;
		}

}
int pibonacci(int n){


		int temp;

		if( n==0 )
				return 0;
		else if(n==1)
				return 1;
		else 
				temp = pibonacci(n-1) + pibonacci(n-2);


		return temp;
			
}
int sum_of_four_integers(int a, int b, int c, int d){

		return a+b+c+d;

}
int open(const char *file){

		//입력받은 이름에 해당하는 파일이 있는지 찾아봐야해
		
		struct file* temp; //이걸로 파일이 존재했는지, filesys_open의 return 값 저장
		struct thread* nowthread; //이거는 현재의 thread를 가리키게 하여 그 thread가 자신이 불러내는 file을 저장하도록 한다.
		int index;
		int amount;
        int error;
		temp = NULL;
		nowthread = NULL;

        error = 0; //error not yet
		if(file==NULL){
            error = -1;
            return -1;
        }
        else error = 0;

		nowthread = thread_current();
		if(nowthread == NULL){
			  error = -1;	
              return -1;//현재 돌아가는 thread가 없거나, 아니면 filename을 받지못한경우 error
        }
        else error = 0;

	  
        //여기서 수정할 필요가 있단다 
		temp = filesys_open(file);
		
		amount = 80;
		
		if(temp ==  NULL){

				while(1){
					if(temp !=NULL) break;
					if(amount ==0) break;
					temp = filesys_open(file);
					if(temp !=NULL) break;
					amount--;
				}
		}
		if(temp == NULL){ //즉, file이름에 해당하는 파일이 존재하지 않는다.
			  error = -1;	
              return -1;
        }
        else error = 0;
		
		if( denying(file)==1 ){

          file_deny_write(temp);
        }

        //이미 실행중인 파일이라면, 



        if(error ==0 ){
            nowthread->openfd += 1;

            index = nowthread->openfd; //열려있는 fd가 얼마만큼있는지 받아와서 list에 그수에 해당하는 인덱스 새로운거 추가
            //여기다가 줄줄이 파일 여는 거 저장할꺼야, thread.h에 있는 file list야 
            nowthread->fileList[index]  = temp;
            strlcpy(nowthread->openfilename[index],file,strlen(file)+1);

            return index; 
        }
        else return -1;
}
bool create(const char *file, unsigned initial_size){

		//기존에 존재하는 파일이라면 오히려 open 과 다르게 error야
		//그걸 해주기 전에, 일단 file이 NULL은 아닌지
		struct file* temp;
        int error = 0;
		if(file == NULL){
                error = -1;
				exit(-1);
        }
        else error =0;

		temp = filesys_open(file);
		if(temp !=NULL){ //기존에 파일이 존재하는 경우
				return false;
                error = -1;
        }
        else error = 0;
		//여기 수정해야 하나!
	
		
		return (bool)filesys_create(file,initial_size);

}
bool remove(const char *file){


		bool TF;
		if(file == NULL) return false;
		TF =  filesys_remove(file);
		return TF;

}
int filesize(int fd){

		struct file* nowfile;
		struct thread* nowthread;
		int size;
        int error = 0;
		
		nowthread = thread_current();
		if(nowthread == NULL){ 
                error = -1;
				return -1;
        }
		else{
                error = 0;
				nowfile = (struct file*)(nowthread->fileList[fd]);
				if(nowfile==NULL){
                        error = -1;
						return -1;
                }
				size = file_length(nowfile);
		}
		return size;

}
void seek(int fd, unsigned position){

		struct file* nowfile;
		struct thread* nowthread;
        int error =0;

		nowthread = thread_current();
		if(nowthread == NULL){
            error = -1;
            exit(-1);
        } 
		nowfile = (struct file*)(nowthread->fileList[fd]);
		if(nowfile == NULL){
            error = -1;
            return;
        } 
        else error = 0;
		
		file_seek(nowfile,(off_t)position);

}
unsigned tell(int fd){

		//file_tell : returns the current position in file as a byte offset from the start of the file
		int error = 0;
		struct file* nowfile;
		struct thread* nowthread;
		
		nowthread = thread_current();
		
        if(nowthread == NULL ){
            error = -1;
        }
		if(error == -1) exit(-1);
        else error = 0;

		nowfile = (struct file*)(nowthread->fileList[fd]);
		if(nowfile == NULL) error = -1;
		if(error == -1) exit(-1);
        else error = 0;
		
		return (unsigned)file_tell(nowfile);

}
void close(int fd){

		struct file* nowfile;
		struct thread* nowthread;

		int error = 0;
		nowthread = thread_current();
		if(nowthread == NULL){
				//printf(" in close function : thread_current() return값이 NULL입니다\n");
				error = -1;
				exit(-1);
		}
        else error =0;
		if( nowthread->fileList[fd] == NULL){
				error = -1;
				exit(-1);
		}
        else error = 0;
		nowfile = (struct file*)(nowthread->fileList[fd]);
		//수정해주어야 하나
		
		file_close(nowfile);
		if( error == -1)exit(-1);
        else error =0;
		nowthread->fileList[fd] = NULL;
}
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
		uint32_t byte_4;
		uint32_t stackaccess;
		int sysCall_number;
		byte_4 = 4;
		
		if( f->esp == NULL) exit(-1);
		
		
		stackaccess = (uint32_t)(f->esp);

        if(try == 1){
        //first time
            sema_init(&mutex,1);
        }
        
        try++;

/*
		if( lock == false ){



		}

*/
		if( stackaccess + byte_4 >= LOADER_PHYS_BASE){
				//printf(" LOADER_PHYS_BASE를 넘어가버린다\n");
				exit(-1);
		}

		sysCall_number = *(int*)(f->esp);
		
		
		switch(sysCall_number){
				case SYS_HALT:
						halt();
						break;
				case SYS_EXIT:
						if(!is_user_vaddr(f->esp+4) ){

								//printf(" esp 잘못된곳을 참조하고 있습니다.\n");
								exit(-1);
						}
						exit( *(uint32_t*)(f->esp + 4));
						break;
				case SYS_EXEC:
						if(is_kernel_vaddr(f->esp+4) ){

								//printf(" esp 잘못된곳을 참조하고 있습니다.\n");
								exit(-1);
						}

						f->eax = exec((const char*)*(uint32_t*)(f->esp+4));
						break;
				case SYS_WAIT:
						if(is_kernel_vaddr(f->esp+4) ){

								//printf(" esp 잘못된곳을 참조하고 있습니다.\n");
								exit(-1);
						}
						f->eax = wait((pid_t)*(uint32_t*)(f->esp+4));
						break;
				case SYS_READ:
                        sema_down(&mutex);
						if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8) || !is_user_vaddr(f->esp + 12)){
								//printf(" esp 잘못된곳을 참조하고 있습니다.\n");
								exit(-1);
						}
						f->eax = read((int)*(uint32_t*)(f->esp+4),(void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t *)(f->esp + 12)));
                        sema_up(&mutex);
						break;
				case SYS_WRITE:
                        sema_down(&mutex);
						if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8) || !is_user_vaddr(f->esp + 12)){

								//printf(" esp 잘못된곳을 참조하고 있습니다.\n");
								exit(-1);
						}
        
						f->eax = write((int)*(uint32_t*)(f->esp+4),(void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t *)(f->esp + 12)));
                        sema_up(&mutex);
						break;
				case SYS_pibo:
						f->eax = pibonacci((int)*(uint32_t*)(f->esp+4));
						break;
				case SYS_sum:
						f->eax = sum_of_four_integers((int)*(uint32_t*)(f->esp+4),(int)*(uint32_t*)(f->esp+8),(int)*(uint32_t*)(f->esp+12),(int)*(uint32_t*)(f->esp+16));
						break;
				case SYS_CREATE:
						f->eax = create(*(const char**)(f->esp+4),*(unsigned int*)(f->esp+8));
						break;
				case SYS_OPEN:
                        sema_down(&mutex);
						f->eax = open(*(const char**)(f->esp+4));
                        sema_up(&mutex);
						break;
				case SYS_REMOVE:
						f->eax = remove(*(const char**)(f->esp+4));
						break;
				case SYS_FILESIZE: 
						f->eax = filesize(*(int*)(f->esp+4));
						break;
				case SYS_SEEK:
						seek(*(int*)(f->esp+4),*(unsigned*)(f->esp+8));
						break;
				case SYS_TELL:
						f->eax = tell(*(int*)(f->esp+4));
						break;
				case SYS_CLOSE:
						close(*(int*)(f->esp+4));
						break;
        }
		
}
