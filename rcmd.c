#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

const char *rcmd_version_string = "0.2.9";

char *signature = "\x16\x02";
char mask = 0xAA;
int debug, errnum, is_daemon, is_listen;
pid_t pid;
int socket_fd, peer_socket_fd;
char *local_ip, *remote_ip;
unsigned int port;
char buffer[4096];
size_t bufsize = 4096;
char *pwd_filename;
char *key_filename;

static const struct option long_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{"debug", no_argument, NULL, 'D'},
	{"daemon", no_argument, NULL, 'd'},
	{"genkey", required_argument, NULL, 'g'},
	{"hostname", required_argument, NULL, 'H'},
	{"keyname", required_argument, NULL, 'k'},
	{"remote-ip", required_argument, NULL, 'I'},
	{"local-ip", required_argument, NULL, 'i'},
	{"listen", no_argument, NULL, 'l'},
	{"port", required_argument, NULL, 'p'},
	{"test", no_argument, NULL, 't'},
	{NULL, 0, NULL, 0}
};
static const char *short_options = "hVDdg:H:I:i:k:lp:t";

void Help(void) {
printf("Usage: rcmd { -h/--help | -V/--version | -D/--debug | -d/--daemon | -g/--genkey }\n"
"\t{ -k/--keyname | -I/--remote-ip | -i/--local-ip | -l/--listen | -p/--port | -t/--test }\n");
}

// Key used when there's no key, otherwise changed by GenKey() or LoadKey()
char keylist[95][3] = 
{{' ','2'},{'!','5'},{'"','3'},{'#','7'},{'$','9'},{'%','8'},{'&','1'},{'\'','6'},
{'(','0'},{')','4'},{'*','z'},{'+','y'},{',','u'},{'-','w'},{'.','v'},{'/','x'},
{'0','q'},{'1','p'},{'2','r'},{'3','t'},{'4','s'},{'5','m'},{'6','n'},{'7','o'},
{'8','l'},{'9','k'},{':','j'},{';','i'},{'<','h'},{'=','g'},{'>','f'},{'?','e'},
{'@','d'},{'A','c'},{'B','b'},{'C','a'},{'D','~'},{'E','}'},{'F','|'},{'G','{'},
{'H','`'},{'I','_'},{'J','^'},{'K',']'},{'L','\\'},{'M','['},{'N','A'},{'O','H'},
{'P','U'},{'Q','O'},{'R','Z'},{'S',':'},{'T','*'},{'U','$'},{'V','C'},{'W','I'},
{'X','T'},{'Y','N'},{'Z','?'},{'[',';'},{'\\',')'},{']','#'},{'^','B'},{'_','J'},
{'`','V'},{'a','Q'},{'b','<'},{'c',','},{'d','('},{'e','"'},{'f','D'},{'g','L'},
{'h','W'},{'i','P'},{'j','='},{'k','+'},{'l','\''},{'m','!'},{'n','E'},{'o','K'},
{'p','Y'},{'q','R'},{'r','>'},{'s','.'},{'t','&'},{'u',' '},{'v','F'},{'w','M'},
{'x','X'},{'y','S'},{'z','/'},{'{','-'},{'|','%'},{'}','@'},{'~','G'}};

void RandomizeKey(void) {
	int cnt = 0, cnt2;
	char ctmp;
	srand((unsigned int)time(NULL));
	while (1) {
		cnt2 = rand()%94;
		ctmp = keylist[cnt][1];
		keylist[cnt][1] = keylist[cnt2][1];
		keylist[cnt2][1] = ctmp;

		if (++cnt >= 95)
			break;
	}
	
	if (debug) {
		cnt = 0;
		while (1) {
			fputc(keylist[cnt][1], stdout);
			fflush(stdout);

			++cnt;
			if (cnt >= 95)
				break;
		}
		printf("\n");
	}
}

void GenKey(char *keyname) {
	char *filename;
	if (strlen(keyname) == 0) {
		filename = malloc(strlen("rcmd.key")+1);
		sprintf(filename, "rcmd.key");
	}
	else {
		filename = malloc(strlen(keyname)+1);
		sprintf(filename, "%s", keyname);
	}

	RandomizeKey();

	FILE *fp = fopen(filename, "w");
	if (fp == NULL) {
		printf("GenKey() error: Cannot open %s: %s\n", filename, strerror(errno));
		free(filename);
		return;
	}

	int cnt = 0;
	while (1) {
		fputc(keylist[cnt][1], fp);
		if (++cnt >= 95)
			break;
	}

	fclose(fp);

	return;
}

void LoadKey(char *keyname) {
	char *filename;
	if (strlen(keyname) == 0) {
		filename = malloc(strlen("rcmd.key")+1);
		sprintf(filename, "rcmd.key");
	}
	else {
		filename = malloc(strlen(keyname)+1);
		sprintf(filename, "%s", keyname);
	}

	FILE *fp = fopen(filename, "r");
	if (fp == NULL) {
		// ignore this message since we can run without key files
		//printf("LoadKey() error: Cannot open %s: %s\n", filename, strerror(errno));
		free(filename);
		return;
	}

	int cnt = 0;
	while (1) {
		keylist[cnt][1] = fgetc(fp);
		if (++cnt >= 95)
			break;
	}

	fclose(fp);

	return;
}

char DemixChar(char c) {
	if (c < 32 || c > 126)
		return c;

	int cnt;
	for (cnt=0; cnt < 95; cnt++) {
		if (keylist[cnt][1] == c)
			return keylist[cnt][0];
	}

	return 1;
}

char MixChar(char c) {
	if (c < 32 || c > 126)
		return c;

	return keylist[c-32][1];
}

char *Demix(char *data) {
	char *buf = malloc(strlen(data)+1);
	int cnt = 0, cnt2 = 0;
	while (1) {
		if (data[cnt2] == '\n' && data[cnt2+1] == signature[0] &&
			data[cnt2+2] == signature[1]) {
			buf[cnt++] = '\n';
			cnt2 += strlen(signature)+1;
			continue;
		}
		buf[cnt++] = DemixChar(data[cnt2++]/*^mask*/);
		if (data[cnt2] == '\0') {
			buf[cnt] = '\0';
			break;
		}
	}

	return buf;
}

char *Mix(char *data) {
	char *buf = malloc(strlen(data)+1);
	int cnt = 0;
	while (1) {
		buf[cnt] = MixChar(data[cnt]);
		//buf[cnt] ^= mask;
		++cnt;
		if (data[cnt] == '\0') {
			buf[cnt] = '\0';
			break;
		}
	}

	return buf;
}

void Test(void) {
	char *str = "This is a test text";
	printf("%s\n", str);

	char *str2 = Mix(str);
	printf("%s\n", str2);

	char *str3 = Demix(str2);
	printf("%s\n", str3);
}

// Function for the host (home) running the commands sent from remote server
void Connect(void) {
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "rcmd error: Cannot create socket: %s\n", strerror(errno));
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_addr.s_addr = inet_addr(local_ip);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		errnum = errno;
		fprintf(stderr, "rcmd error: Cannot bind() %s: %s\n", local_ip, strerror(errnum));
		close(socket_fd);
		socket_fd = 0;
		return;
	}
	else {
		if(debug)
			printf("bind() %s successful\n", local_ip);
	}
	
	struct sockaddr_in host;
	bzero(&addr, sizeof(addr));
	host.sin_addr.s_addr = inet_addr(remote_ip);
	host.sin_family = AF_INET;
	host.sin_port = htons(port);
	if(debug)
		printf("connecting %s...\n", remote_ip);
	if (connect(socket_fd, (struct sockaddr *)&host, sizeof(host)) < 0) {
		errnum = errno;
		fprintf(stderr, "rcmd error: Cannot connect() %s: %s\n", remote_ip, strerror(errnum));
		close(socket_fd);
		socket_fd = 0;
		return;
	}
	else {
		if(debug)
			printf("connect() %s successful\n", remote_ip);
	}

	char output_filename[64];
	memset(output_filename, 0, 64);
	sprintf(output_filename, "/tmp/rcmd.%d", pid);
	ssize_t bytes_read;
	char *str2 = NULL;
	while (1) {
		memset(buffer, 0, 4096);
		if(debug)
			printf("reading command...\n");
		bytes_read = read(socket_fd, buffer, bufsize);

		if (strncmp(buffer, signature, strlen(signature)) != 0)
			continue;

		if (bytes_read > 0)
			str2 = Demix(buffer+2);
		else {
			str2 = malloc(4096);
			memset(str2, 0, 4096);
			sprintf(str2, "%s", buffer+2);
		}
		
		if (bytes_read == 0 || strcmp(str2, "qw\n") == 0) {
			if (debug)
				printf("breaking loop\n");
			break;
		}

		if (str2[strlen(str2)-1] == '\n')
			str2[strlen(str2)-1] = '\0';
	
		if (debug)
			printf("running \"%s\"\n", str2);
		int strsize = strlen("bash -c 'cd `cat /tmp/rcmd-pwd.0000000`; ") +
			strlen(str2) + strlen("; pwd >/tmp/rcmd-pwd.0000000") +
			strlen("' &>") + strlen(output_filename) + 1;
		char *cmdstr = malloc(strsize);
		memset(cmdstr, 0, strsize);
		sprintf(cmdstr, "bash -c 'cd `cat %s`; %s; pwd >%s' &>%s", 
			pwd_filename, str2, pwd_filename, output_filename);
		system(cmdstr);
		free(cmdstr);
		free(str2);

		FILE *fp = fopen(output_filename, "r");
		if (fp == NULL) {
			if (debug)
				printf("rcmd error: Cannot open %s: %s\n", output_filename,
					strerror(errno));
			sprintf(buffer, "Cannot open %s: %s\n", output_filename, strerror(errno));
			write(socket_fd, buffer, strlen(buffer));
			continue;
		}
		char *line = malloc(4096);
		size_t linesize = 4096;
		ssize_t bytes_read;
		char *str3 = malloc(4096+strlen(signature)+1);
		memset(str3, 0, 4096+strlen(signature));
		while (1) {
			if (debug)
				printf("reading cmd.output\n");
			memset(line, 0, 4096);
			bytes_read = getline(&line, &linesize, fp);
			if (bytes_read > 0)
				str2 = Mix(line);

			if (debug)
				printf("bytes_read: %ld\n", (long)bytes_read);

			if (bytes_read <= 0) {
				memset(buffer, 0, 4096);
				buffer[0] = -1;
				write(socket_fd, buffer, 1);
				break;
			}
			if (debug) {
				printf("%s\n", line);
				printf("%s\n", str2);
			}
			if (str2[strlen(str2)-1] == -1) {
				write(socket_fd, str2, bytes_read);
				free(str2);
				break;
			}

			sprintf(str3, "%s", signature);
			strcat(str3, str2);
			write(socket_fd, str3, bytes_read+strlen(signature));
			memset(str3, 0, 4096+strlen(signature));
			free(str2);
		}
		fclose(fp);
	}

	close(socket_fd);
	socket_fd = 0;
}

// Function for remote server (cloud) sending commands executed home
void Listen(void) {
	socket_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		fprintf(stderr, "rcmd error: Cannot create socket: %s\n", strerror(errno));
		exit(errno);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_addr.s_addr = inet_addr(local_ip);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (bind(socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		errnum = errno;
		fprintf(stderr, "rcmd error: Cannot bind() %s: %s\n", local_ip, strerror(errnum));
		close(socket_fd);
		socket_fd = 0;
		exit(errnum);
	}
	else {
		if (debug)
			printf("bind() %s successful\n", local_ip);
	}

	if (debug)
		printf("listening...\n");
	if (listen(socket_fd, 1) < 0) {
		errnum = errno;
		fprintf(stderr, "rcmd error: Cannot listen(): %s\n", strerror(errnum));
		close(socket_fd);
		socket_fd = 0;
		exit(errnum);
	}

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_size = sizeof(struct sockaddr_in);
	peer_socket_fd = accept(socket_fd, (struct sockaddr *)&peer_addr,
		&peer_addr_size);
	if (peer_socket_fd < 0) {
		errnum = errno;
		fprintf(stderr, "rcmd error: Cannot accept(): %s\n", strerror(errnum));
		close(socket_fd);
		socket_fd = 0;
		exit(errnum);
	}
	printf("connected\n");

	char *line = malloc(4096);
	size_t linesize = 4096;
	ssize_t bytes_read;
	char *str2 = NULL;
	char str3[4096+strlen(signature)];
	memset(str3, 0, 4096+strlen(signature));
	while (1) {
		if (debug)
			printf("reading input...\n");
		memset(line, 0, 4096);
		bytes_read = getline(&line, &linesize, stdin);
		if (line[0] == '\n')
			continue;
		str2 = Mix(line);
		if (bytes_read == 0 || strcmp(line, "qw\n") == 0) {
			sprintf(str3, "%s", signature);
			strcat(str3, str2);
			write(peer_socket_fd, str3, strlen(str3));
			memset(str3, 0, 4096+2);
			free(str2);
			sleep(2);
			break;
		}

		if (debug)
			printf("sending line\n");
		sprintf(str3, "%s", signature);
		strcat(str3, str2);
		write(peer_socket_fd, str3, strlen(str3));
		memset(str3, 0, 4096+2);
		free(str2);

		while (1) {
			if (debug)
				printf("reading response\n");
			memset(buffer, 0, 4096);
			bytes_read = read(peer_socket_fd, buffer, 4096);
			if (bytes_read <= 0)
				break;
			else if (buffer[0] == -1)
				break;

			if (strncmp(buffer, signature, strlen(signature)) != 0) {
				printf("Wrong signature!\n");
				break;
			}

			str2 = Demix(buffer+strlen(signature));

			if (str2[strlen(str2)-1] == -1) {
				str2[strlen(str2)-1] = '\0';
				printf("%s", str2);
				fflush(stdout);
				free(str2);
				break;
			}
			printf("%s", str2);
			fflush(stdout);
			free(str2);
		}
	}

	close(socket_fd);
	socket_fd = 0;
}

char *GetIP(char *hostname) {
    struct hostent *he;
    struct in_addr **addr_list;
    int cnt = 0;

    he = gethostbyname(hostname);
    if (he == NULL) {
        fprintf(stderr, "##codybot::ServerGetIP() error: Cannot gethostbyname()\n");
        exit(1);
    }

    addr_list = (struct in_addr **)he->h_addr_list;

    char *ipstr = inet_ntoa(*addr_list[0]);
    if (debug) {
        for (cnt = 0; addr_list[cnt] != NULL; cnt++) {
            printf("%s\n", inet_ntoa(*addr_list[cnt]));
        }
    }

	return ipstr;
}

void rcmdExit(void) {
	if (debug)
		printf("rcmd exiting\n");
	
	if (is_daemon) {
		char str[1024];
		sprintf(str, "rm %s", pwd_filename);
		system(str);
	}

	if (is_listen && peer_socket_fd > 0)
		close(peer_socket_fd);
	if (socket_fd > 0)
		close(socket_fd);
}

void rcmdSignal(int signum) {
	switch(signum) {
	case SIGINT:
		exit(0);
		break;
	}
}

int main(int argc, char **argv) {
	pid = getpid();
	if (debug)
		printf("rcmd started PID %d\n", pid);
	
	if (getuid() == 0)
		setuid(1000);

	atexit(rcmdExit);
	signal(SIGINT, rcmdSignal);

	int c;
	while (1) {
		c = getopt_long(argc, argv, short_options, long_options, NULL);
		
		if (c == -1)
			break;
		
		switch(c) {
		case 'h':
			Help();
			exit(0);
			break;
		case 'V':
			printf("rcmd %s\n", rcmd_version_string);
			exit(0);
			break;
		case 'D':
			debug = 1;
			break;
		case 'd':
			is_daemon = 1;
			break;
		case 'g':
			GenKey(optarg);
			exit(0);
			break;
		case 'H':
			remote_ip = GetIP(optarg);
			break;
		case 'I':
			if (optarg[0] == '-')
				fprintf(stderr, "rcmd error: -I argument must be an IP address\n");
			else {
				remote_ip = malloc(strlen(optarg)+1);
				sprintf(remote_ip, "%s", optarg);
				printf("remote_ip: %s\n", remote_ip);
			}
			break;
		case 'i':
			if (optarg[0] == '-')
				fprintf(stderr, "rcmd error: -i argument must be an IP address\n");
			else {
				local_ip = malloc(strlen(optarg)+1);
				sprintf(local_ip, "%s", optarg);
				printf("local_ip: %s\n", local_ip);
			}
			break;
		case 'k':
			if (strlen(optarg) == 0) {
				key_filename = malloc(strlen("rcmd.key")+1);
				sprintf(key_filename, "rcmd.key");
			}
			else {
				key_filename = malloc(strlen(optarg)+1);
				sprintf(key_filename, "%s", optarg);
			}
			break;
		case 'l':
			is_listen = 1;
			break;
		case 'p':
			if (optarg[0] == '-')
				fprintf(stderr, "rcmd error: -p argument requires a port number\n");
			else
				port = atoi(optarg);
			break;
		case 't':
			Test();
			exit(0);
			break;
		}
	}

	if (key_filename == NULL) {
		key_filename = malloc(strlen("rcmd.key")+1);
		sprintf(key_filename, "rcmd.key");
	}
	LoadKey(key_filename);

	if (local_ip == NULL) {
		local_ip = malloc(strlen("0.0.0.0")+1);
		sprintf(local_ip, "0.0.0.0");
	}

	if (remote_ip == NULL)
		remote_ip = GetIP("hobby.esselfe.ca");

	if (port == 0)
		port = 16422;

	if (is_daemon) {
		if (debug)
			printf("running as a daemon\n");

		pwd_filename = malloc(strlen("/tmp/rcmd-pwd.0000000")+1);
		sprintf(pwd_filename, "/tmp/rcmd-pwd.%d", pid);
		char str[1024];
		sprintf(str, "cd $HOME; pwd >%s", pwd_filename);
		system(str);

		while (1) {
			Connect();
			sleep(5);
		}
	}

	if (is_listen) {
		if (debug)
			printf("running as listen\n");
		Listen();
	}

	return 0;
}

