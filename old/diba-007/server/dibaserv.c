
/* =====[ dibaserv.c ]=========================================================

   Description:     Server process for DIBA. Will spawn worker process.

   Revisions:

      REV   DATE            BY              DESCRIPTION
      ----  -----------     ----------      ------------------------------
      0.00  dec.21.2017     Peter Glen      Initial
      
   ======================================================================= */

#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>

// FIXME: Windoze now, will do Lnux soon
//#include <sys/socket.h>
#include <winsock2.h>

//#include <netinet/in.h>
#include <wininet.h>

#include <string.h>

#include "diba.h"
#include "gcrypt.h"
#include "gcry.h"
#include "getpass.h"
#include "gsexp.h"
#include "base64.h"
#include "zmalloc.h"
#include "cmdline.h"
#include "dibastr.h"
#include "misc.h"
#include "zstr.h"
#include "dibafile.h"

static  unsigned int keysize = 2048;

static int weak = FALSE;
static int force = FALSE;
static int dump = 0;
static int verbose = 0;
static int test = 0;
static int foreg = 0;
static int calcsum = 0;
static int nocrypt = 0;
static int version = 0;

static int ver_num_major = 0;
static int ver_num_minor = 0;
static int ver_num_rele  = 4;

static char descstr[] = "Listen for DIBA broadcasts ";
static char usestr[]  = "dibaserv [options]\n";
                
static char    *thispass = NULL;
static char    *keyname  = NULL;
static char    *keydesc  = NULL;
static char    *creator  = NULL;
static char    *errout   = NULL;

/*  char    opt;
    char    *long_opt;
    int     *val;
    char    *strval;
    int     minval, maxval;
    int     *flag;
    char    *help; */
    
opts opts_data[] = {

        'k',   "keylen",   &keysize,  NULL,  1024, 32768,    NULL, 
        "-k             --keylen      - key length in bits (default 2048)",
        
        'v',   "verbose",  NULL, NULL,  0, 0, &verbose, 
        "-v             --verbose     - Verbosity on",
        
        'V',   "version",  NULL, NULL,  0, 0, &version, 
        "-V             --version     - Print version numbers and exit",
        
        'u',   "dump",  NULL, NULL,  0, 0,    &dump, 
        "-u             --dump        - Dump key to terminal",
        
        't',   "test",  NULL,  NULL, 0, 0, &test, 
        "-t             --test        - run self test before proceeding",
        
        's',   "sum",  NULL,  NULL, 0, 0, &calcsum, 
        "-s             --sum         - print sha sum before proceeding",
        
        'f',   "force",  NULL,  NULL, 0, 0, &force, 
        "-f             --force       - force clobbering files",
        
        'w',   "weak",  NULL,  NULL, 0, 0, &weak, 
        "-w             --weak        - allow weak pass",
        
        'n',   "nocrypt",  NULL,  NULL, 0, 0, &nocrypt, 
        "-n             --nocrypt     - do not encrypt key (testing only)",
        
        'p',   "pass",   NULL,   &thispass, 0, 0,    NULL, 
        "-p val         --pass val    - pass in for key (@file reads pass from file)",
        
        'm',   "keyname",  NULL,   &keyname, 0, 0, NULL, 
        "-m name        --keyname nm  - user legible key name",
       
        'd',   "desc",  NULL,      &keydesc, 0, 0, NULL, 
        "-d desc        --desc  desc  - key description",
       
        'e',   "errout",  NULL,  &errout, 0, 0, NULL, 
        "-e fname       --errout fnm  - dup stderr to file. (for GUI deployment)",
       
        'f',   "foreground",  NULL,   NULL, 0, 0, &foreg, 
        "-f            --foreground   - stay in foreground",
       
        0,     NULL,  NULL,   NULL,   0, 0,  NULL, NULL,
        };


void my_progress_handler (void *cb_data, const char *what,
                            int printchar, int current, int total)
{
    printf(".");
    //printf("%c", printchar);
}

static void myfunc(int sig)
{
    printf("\nSignal %d (segment violation)\n", sig);
    exit(111);
}

static void myfunc2(int sig)
{
    //printf("\nSignal %d\n", sig);
    signal(sig, myfunc2);
    //exit(111);
}

int winfork(char *cmd, int ClientSocket)

{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    struct sockaddr_in saddr;
    socklen_t  addrlen = sizeof(saddr);
    int retp = getpeername(ClientSocket,  
                              (struct sockaddr *)&saddr, &addrlen);
    if(retp < 0)
        {
        xerr2("Error on getpeername. %d (errno %d %s)\n", 
                            retp, errno, strerror(errno));
        } 
        
    char *ipstr = inet_ntoa(saddr.sin_addr);
    int ppp = ntohs(saddr.sin_port);
    
    printf("Connection from:  %s on port %d\n", ipstr, ppp);

    char arr[MAX_PATH];
    snprintf(arr, sizeof(arr), "%s %d %s %d ", 
                            cmd, ClientSocket, ipstr, ppp);
    
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    si.hStdInput = (HANDLE)ClientSocket;
    si.hStdOutput = (HANDLE)ClientSocket;
    //si.hStdError = (HANDLE)ClientSocket;
    
    //FILE *logfp = fopen("dibaserv.log", "ab+");
    //if(!logfp)
    //    {
    //    xerr2("Cannot open log file.\n");
    //    }
    //si.hStdError = (HANDLE)fileno(logfp);
    
    ZeroMemory( &pi, sizeof(pi) );
    
     if( !CreateProcess( NULL,   // No module name (use command line)
        arr,            // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        TRUE,           // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi )           // Pointer to PROCESS_INFORMATION structure
    ) 
    {
        printf( "CreateProcess failed (%d).\n", GetLastError() );
        return 0;
    }
    
    return 1;
}

// -----------------------------------------------------------------------
// Chain to err routine, dup error to file first 
// See if any other freeing action is requested

void    xerr3(const char *str, ...)

{
    va_list ap;
    va_start(ap, str);    
    
    FILE* errf = fopen(errout, "wb");
    // Ignore error, empty or non existant file will indicate error to caller
    if (errf) {
        vfprintf(errf, str, ap);
        fclose(errf);
    }
    
    va_list ap2;
    va_start(ap2, str);    
    xerr2(str, ap2); 
}
    
// -----------------------------------------------------------------------

int main(int argc, char** argv)
{
    signal(SIGSEGV, myfunc);
    signal(SIGINT, myfunc2);
    
    //signal(SIGTERM, myfunc2);
    //signal(SIGCHLD,SIG_IGN); /* ignore child */
	//signal(SIGTSTP,SIG_IGN); /* ignore tty signals */
	//signal(SIGTTOU,SIG_IGN);
	//signal(SIGTTIN,SIG_IGN);
	//signal(SIGHUP,myfunc); /* catch hangup signal */

    zline2(__LINE__, __FILE__);
    char    *dummy = alloc_rand_amount();
    
    // Pre allocate all string items    
    //char *mstr = "No Memory";
    zline2(__LINE__, __FILE__);
    thispass = zalloc(MAX_PATH); if(thispass == NULL) xerr3(mstr);
    keyname  = zalloc(MAX_PATH); if(keyname  == NULL) xerr3(mstr);
    keydesc  = zalloc(MAX_PATH); if(keydesc  == NULL) xerr3(mstr);
    creator  = zalloc(MAX_PATH); if(creator  == NULL) xerr3(mstr);
    errout   = zalloc(MAX_PATH); if(errout   == NULL) xerr3(mstr);
    
    char *err_str = NULL;
    int nn = parse_commad_line(argv, opts_data, &err_str);
    
    //printf("Processed %d comline entries\n", nn);
    
    if (err_str)
        {
        printf(err_str);
        usage(usestr, descstr, opts_data); exit(2);
        }
    if(errout[0] != '\0')
        {
        //printf("removing %s\n", errout);
        unlink(errout);
        }
    if(version)
        {
        printf("dibaserv version %d.%d.%d\n", ver_num_major, ver_num_minor, ver_num_rele);
        printf("libgcrypt version %s\n", GCRYPT_VERSION);
        exit(1);
        }
    if(thispass[0] != '\0')
        {
        if(nocrypt)
            xerr3("dibaserv: \nConflicting options, cannot provide key with the 'nocrypt' flag.\n");
        }
    if(num_bits_set(keysize) != 1)
        {
        xerr3("dibaserv: Keysize must be a power of two. ( ... 1024, 2048, 4096 ...)");
        } 
    gcrypt_init();

    if(calcsum)
        {
        char *err_str, *hash_str = hash_file(argv[0], &err_str);
        if(hash_str != NULL)
            {
            printf("Executable sha hash: '%s'\n", hash_str);
            zfree(hash_str);
            }
        else 
            {
            xerr3("dibaserv: %s\n", err_str);
            }
        }
    
    if(test)
        {
        printf("Excuting self tests ... ");
        gcry_error_t err = 0;
        err = gcry_control(GCRYCTL_SELFTEST);
        if(err)
            {
            printf("fail.\n");
            exit(3);
            }
        else
            {
            printf("pass.\n");
            }
        }
   
    //if (argc - nn != 2) {
    //    printf("dibaserv: Missing argument");
    //    usage(usestr, descstr, opts_data); exit(2);
    //    }
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        xerr2("Socket start failed. Error Code : %d", WSAGetLastError());
    }
    
    // Touch logfile (for debug)
    FILE *logfp = fopen("dibaserv.log", "ab+");
    if(!logfp)
        {
        xerr2("Cannot open log file.\n");
        }
    fclose(logfp);
    //syslog(LOG_INFO, "Connection from host %d", callinghostname);
    // Daemonize
    if(!foreg)
        {
        int fd0 = open("\\.\\nul", _O_RDWR);
        if(fd0 < 0)
            {
            xerr2("Cannot open nul file.\n");
            }
        dup2(fd0, 0);
        dup2(fd0, 1);
        dup2(fd0, 2);
        }
    
    int   welcomeSocket, newSocket;
    char  buffer[1024];
    struct sockaddr_in serverAddr;
    struct sockaddr_storage serverStorage;
    socklen_t addr_size;
    
    welcomeSocket = 
        WSASocket (AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0); 
    //socket (PF_INET, SOCK_STREAM, 0);
    
    /*---- Configure settings of the server address struct ----*/
    serverAddr.sin_family = AF_INET;
    /* Set port number, using htons function to use proper byte order */
    serverAddr.sin_port = htons(6789);
    /* Set IP address to localhost */
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    //serverAddr.sin_addr.s_addr = inet_addr(INADDR_ANY);
    
    /* Set all bits of the padding field to 0 */
    memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  
    
    /*---- Bind the address struct to the socket ----*/
    int err = bind(welcomeSocket, (struct sockaddr *) &serverAddr, 
                            sizeof(serverAddr));
    if(err < 0)
       xerr2("Error on socket bind. %d (errno %d %s)\n", 
                            err, errno, strerror(errno));
    
    /*---- Listen on the socket, with 5 max connection requests queued ----*/
    
    while(1)
        {
        err = listen(welcomeSocket, 5);
        if(err)
            xerr2("Error on socket listening. %d (errno %d %s)\n", 
                                err, errno, strerror(errno));
        
        printf("Listening .... (pid=%d) \n", getpid());
         
        /*----  the incoming connection ----*/
        addr_size = sizeof serverStorage;
        newSocket = accept(welcomeSocket, (struct sockaddr *) &serverStorage,
                             &addr_size);
        if(newSocket < 0)
            xerr2("Error on socket accept. %d (errno %d %s)\n", 
                                err, errno, strerror(errno));
        
        printf("Accepted connection. on handle: %d\n", newSocket);
        
        pid_t chh = winfork("dibaworker.exe", newSocket);
        if(chh == 0)
            {
            // Child
            printf("Child pid %d\n", chh);
            }
        }
    zfree(thispass);    zfree(keyname);      
    zfree(keydesc);     zfree(creator);
    zfree(errout);
    
    zfree(dummy);
    zleak();
    return 0;
}

/* EOF */













