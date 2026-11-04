#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>

#define PORT 5000
#define MAXCMD 65536
#define MAXOUT 1048576

static void serve(int c){
    char *cmd=malloc(MAXCMD+1); if(!cmd) return;
    size_t n=0; char ch;
    while(n<MAXCMD && read(c,&ch,1)==1 && ch!='\n') cmd[n++]=ch;
    cmd[n]=0;
    if(n==0){ close(c); free(cmd); return; }
    char *full=malloc(MAXCMD+8);
    snprintf(full,MAXCMD+8,"%s 2>&1",cmd);
    FILE *p=popen(full,"r");
    if(!p){ dprintf(c,"RC -1 0\n"); close(c); free(cmd); free(full); return; }
    char *out=malloc(MAXOUT); size_t used=0; size_t r;
    while(used<MAXOUT && (r=fread(out+used,1,MAXOUT-used,p))>0) used+=r;
    int rc=pclose(p);
    dprintf(c,"RC %d %zu\n",rc,used);
    size_t off=0; while(off<used){ ssize_t w=write(c,out+off,used-off); if(w<=0) break; off+=w; }
    close(c); free(cmd); free(full); free(out);
}
int main(){
    signal(SIGPIPE,SIG_IGN);
    int s=socket(AF_VSOCK,SOCK_STREAM,0);
    if(s<0){ perror("socket"); return 1; }
    int one=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));
    struct sockaddr_vm a; memset(&a,0,sizeof(a));
    a.svm_family=AF_VSOCK; a.svm_cid=VMADDR_CID_ANY; a.svm_port=PORT;
    if(bind(s,(struct sockaddr*)&a,sizeof(a))<0){ perror("bind"); return 1; }
    if(listen(s,8)<0){ perror("listen"); return 1; }
    for(;;){ int c=accept(s,0,0); if(c>=0) serve(c); }
    return 0;
}
