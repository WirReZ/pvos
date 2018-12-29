#include "readLine.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <ctype.h>
#include <vector>
#include <signal.h>
#include <wait.h>

#include <sys/ipc.h>
#include <sys/msg.h>
#include <semaphore.h>

/* define HOME to be dir for key and cert files... */
#define HOME "./keys/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "cert.crt"
#define KEYF  HOME  "key.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

#define LIMIT 30
#define SYNCHRONIZE_LIMIT 20
int queue = msgget(0XABCDABCD, 0660 | IPC_CREAT);
sem_t semaphore;
long thread_total_lines = 0;

struct zprava {
	long typ;
	char buf[2048];
};

class Client {
public:
	int fd;
	SSL* ssl;
	SSLReadLine* reader;
	long total_bytes = 0;
	long num_lines = 0;
	Client(int fd, SSL* ssl) {
		this->fd = fd;
		this->reader = new SSLReadLine(fd, ssl, 0);
		this->ssl = ssl;
	}
};
//----------Signal handlers
void sigpipe_handler(int num, siginfo_t* info, void* data) {
}
void sigchld_handler(int num, siginfo_t* info, void* data) {
	int pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
		printf("Server %d finished.\n", pid);
}
//---------- End of signal handlers
//Statistics
void showStatistics(long num, long lines, int seconds) {
	printf("=========== (%d) ===========\n", seconds);
	printf("Clients:%ld, lines:%ld\n", num, lines);
	printf("============================\n");

}
void *run_calculationg_thread_onthread(void * num_clients) {
	int *x_ptr = (int *) num_clients;
	time_t start = time(NULL);
	int seconds = 0;

	while (1) {
		if ((time(NULL) - start) >= LIMIT) {
			seconds += LIMIT;
			showStatistics((*x_ptr), thread_total_lines, seconds);
			start = time(NULL);
		}
		usleep(1000);
	}
}
void *run_calculationg_thread_onprocess(void * num_client) {
	int *x_ptr = (int *) num_client;
	int queue = msgget(0XABCDABCD, 0660 | IPC_CREAT);
	time_t start = time(NULL);
	int seconds = 0;

	long total_lines = 0;
	zprava zp;
	while (1) {
		int len = msgrcv(queue, &zp, sizeof(zp.buf), 1, 0);
		zp.buf[len] = 0;
		long total;
		sscanf(zp.buf, "%ld\n", &total);
		total_lines += total;
		if ((time(NULL) - start) >= LIMIT) {
			seconds += LIMIT;
			showStatistics((*x_ptr), total_lines, seconds);
			start = time(NULL);
		}

	}

	return 0;

}
//End of statistics

void run_server_fork(int* sck, SSL_CTX* ctx) {

	int client_socket = *sck;
	int err;
	zprava zp;
	SSL* ssl = SSL_new(ctx);
	CHK_NULL(ssl);
	SSL_set_fd(ssl, client_socket);
	err = SSL_accept(ssl);
	CHK_SSL(err);
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	Client client = Client(client_socket, ssl);

	long total_bytes = 0;
	long num_lines = 0;
	long int total_queue = 0;
	long int loaded_lines = 0;

	while (1) {
		err = client.reader->readline();
		if (err < 0) {
			printf("%d err\n", err);
			break;
		}
		if (err == 0) { // Disconnected client !
			printf("Client disconnected\n");
			break;
		}

		char *buf = client.reader->toString();

		// parse line
		int tmp, parsed, buf_inx;
		long sum = 0, f_sum = 0, num_linesa = 0, total_bytesa = 0;

		sscanf(buf, "(%d)%n", &tmp, &buf_inx);
		while (1 == sscanf(buf + buf_inx, "%d%n", &tmp, &parsed)) {
			sum += tmp;
			buf_inx += parsed;
		}
		sum /= 2;
		total_bytes += err;

		char sendbuf[4096];
		// send answer
		sprintf(sendbuf, "%ld %ld %ld\n", num_lines, sum, total_bytes);
		num_lines++;
		loaded_lines++;
		if (loaded_lines >= SYNCHRONIZE_LIMIT) {
			zp.typ = 1;
			sprintf(zp.buf, "%ld\n", loaded_lines);
			msgsnd(queue, &zp, strlen(zp.buf), getpid());
			loaded_lines = 0;
		}

		err = SSL_write(client.ssl, sendbuf, strlen(sendbuf));
		CHK_SSL(err);
		if (err == -1) {
			break;
		}

	}
	close(client.fd);
	SSL_free(client.ssl);
}

void* run_server_thread(void* clnt) {
	Client client = *(Client*) clnt;
	long total_bytes = 0;
	long num_lines = 0;
	long queue_num_lines = 0;

	int err;
	while (1) {

		err = client.reader->readline();
		if (err < 0) { // Disconnected client !
			printf("%d err\n", err);
			break;
		}
		if (err == 0) {
			printf("Client disconnected\n");
			break;
		}

		char *buf = client.reader->toString();

		// parse line
		int tmp, parsed, buf_inx;
		long sum = 0, f_sum = 0, num_linesa = 0, total_bytesa = 0; // podle me by melo byt total_bytes a num_lines jinak ! a to kazdy fork mit svuj !

		sscanf(buf, "(%d)%n", &tmp, &buf_inx);
		while (1 == sscanf(buf + buf_inx, "%d%n", &tmp, &parsed)) {
			sum += tmp;
			buf_inx += parsed;
		}
		sum /= 2;
		total_bytes += err;

		char sendbuf[4096];
		// send answer
		sprintf(sendbuf, "%ld %ld %ld\n", num_lines, sum, total_bytes);
		num_lines++;
		queue_num_lines++;
		if(queue_num_lines >= SYNCHRONIZE_LIMIT && sem_trywait(&semaphore) == 0)
		{
			thread_total_lines+=queue_num_lines;
			sem_post(&semaphore);
			queue_num_lines = 0;
		}

		err = SSL_write(client.ssl, sendbuf, strlen(sendbuf));
		CHK_SSL(err);
		if (err == -1) {
			break;
		}

	}

	close(client.fd);
	SSL_free(client.ssl);
	return NULL;
}

int main(int argc, char **argv) {
	int err;
	int master_socket;
	int sd;
	struct sockaddr_in sa_serv;
	struct sockaddr_in sa_cli;
	socklen_t client_len;
	SSL_CTX* ctx;

	X509* client_cert;
	const SSL_METHOD *meth;
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	//Settings for server !!
	int select_flag = 0;
	int process_flag = 0;
	int thread_flag = 0;
	// Settings constants

	//getopt - Select a method to use !
	opterr = 0;
	char * param = NULL;
	char c;
	while ((c = getopt(argc, argv, "spt")) != -1)
		switch (c) {
		case 's':
			select_flag = 1;
			printf("Server starting with Select method !\n");
			break;
		case 'p':
			process_flag = 1;
			printf("Server starting with process method\n");
			break;
		case 't':
			thread_flag = 1;
			printf("Server starting with thread method \n");
			break;
		case '?':
			if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			return 1;
		default:
			abort();
		}

	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	};
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,
				"Private key does not match the certificate public key\n");
		exit(5);
	}

	master_socket = socket(AF_INET, SOCK_STREAM, 0);
	CHK_ERR(master_socket, " listen socket");
	int enable = 1;
	setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));


	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(1111); /* Server Port number */

	err = bind(master_socket, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	CHK_ERR(err, "bind");

	/* Receive a TCP connection. */
	err = listen(master_socket, 5);
	CHK_ERR(err, "listen");
//--------------------- SELECTION METHOD --------------------------------------------
	if (select_flag == 1) {
		struct sigaction action { };
		sigemptyset(&action.sa_mask);
		action.sa_sigaction = sigpipe_handler;
		action.sa_flags = SA_SIGINFO | SA_RESTART;
		sigaction(SIGPIPE, &action, nullptr);

		std::vector<Client> clients;
		long total_num_lines = 0;
		time_t start = time(NULL);
		int seconds = 0;


		while (1) {
			fd_set waiting_set;
			FD_ZERO(&waiting_set);

			FD_SET(master_socket, &waiting_set);
			int last_sd = master_socket;
			//Loop over clients to add client to select

			for (int i = 0; i < clients.size(); i++) {
				FD_SET(clients[i].fd, &waiting_set);
				last_sd = clients[i].fd;
			}

			int sel = select(last_sd + 1, &waiting_set, NULL, NULL, NULL);

			if (sel < 0) {
				printf("Select failed\n");
				exit(1);
			}
			if (FD_ISSET(master_socket, &waiting_set)) {
				client_len = sizeof(sa_cli);
				sd = accept(master_socket, (struct sockaddr*) &sa_cli,
						&client_len);
				CHK_ERR(sd, "accept");

				printf("Connection from %s, port %d\n",
						inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);

				SSL* ssl = SSL_new(ctx);
				CHK_NULL(ssl);
				SSL_set_fd(ssl, sd);
				err = SSL_accept(ssl);
				CHK_SSL(err);
				printf("SSL connection using %s\n", SSL_get_cipher(ssl));

				clients.push_back(Client(sd, ssl));
				//Start timer if not running
				start = time(NULL);

			}

			for (int i = 0; i < clients.size(); i++) {


				if (FD_ISSET(clients[i].fd, &waiting_set)) {

					err = clients[i].reader->readline();
					if (err <= 0) {
						printf("Client %d disconnected !\n", i);
						close(clients[i].fd);
						SSL_free(clients[i].ssl);

						clients.erase(clients.begin() + i);
						continue;
					}

					char *buf = clients[i].reader->toString();

					clients[i].total_bytes += err;

					// parse line
					int tmp, parsed, buf_inx;
					long sum = 0;

					sscanf(buf, "(%d)%n", &tmp, &buf_inx);

					while (1 == sscanf(buf + buf_inx, "%d%n", &tmp, &parsed)) {
						sum += tmp;
						buf_inx += parsed;
					}
					sum /= 2;
					char sendbuf[4096];
					// send answer
					sprintf(sendbuf, "%ld %ld %ld\n", clients[i].num_lines++,
							sum, clients[i].total_bytes);
					total_num_lines++;

					err = SSL_write(clients[i].ssl, sendbuf, strlen(sendbuf));
					CHK_SSL(err);
				}
			}
			if ((time(NULL) - start) >= LIMIT) {
				seconds += LIMIT;
				showStatistics(clients.size(), total_num_lines, seconds);
				start = time(NULL);
			}
		}
	}
//--------------------- PROCESS METHOD --------------------------------------------
	else if (process_flag == 1) {
		struct sigaction action { };
		action.sa_sigaction = sigchld_handler;
		action.sa_flags = SA_SIGINFO | SA_RESTART;
		sigemptyset(&action.sa_mask);
		sigaction(SIGCHLD, &action, nullptr);

		zprava zp;
		zp.typ = 1;
		sprintf(zp.buf, "0");
		msgsnd(queue, &zp, strlen(zp.buf), 0);
		//Start thread for statistic
		int num_clients = 0;
		pthread_t calculate_tid;
		pthread_create(&calculate_tid, nullptr,
				run_calculationg_thread_onprocess, &num_clients);
		//Start processing accepting
		while (1) {
			client_len = sizeof(sa_cli);
			int client_socket = accept(master_socket,
					(struct sockaddr*) &sa_cli, &client_len);
			CHK_ERR(client_socket, "accept");
			num_clients++;
			if (fork() == 0) {
				printf("PID: %d => Connection from %s, port %d\n", getpid(),
						inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);
				run_server_fork(&client_socket, ctx);
			}
		}
		int pid;
		while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
			printf("Server %d finished.\n", pid);
		//pthread_join(calculate_tid, NULL);
	}
//--------------------- THREAD METHOD --------------------------------------------
	else if (thread_flag == 1) {
		std::vector<pthread_t> ssl_tid;
		int i = 0;
		pthread_t calculate_tid;
		pthread_create(&calculate_tid, nullptr,
				run_calculationg_thread_onthread, &i);
		if (sem_init(&semaphore, 0, 1) < 0) {
			perror("sem_init");
			exit(1);
		}
		while (1) {
			client_len = sizeof(sa_cli);
			int client_socket = accept(master_socket,
					(struct sockaddr*) &sa_cli, &client_len);
			CHK_ERR(client_socket, "accept");

			SSL* ssl = SSL_new(ctx);
			CHK_NULL(ssl);
			SSL_set_fd(ssl, client_socket);
			err = SSL_accept(ssl);
			CHK_SSL(err);
			printf("SSL connection using %s\n", SSL_get_cipher(ssl));
			Client client = Client(client_socket, ssl);

			printf("Thread %d started\n", ++i);
			pthread_t tid;
			int ret = pthread_create(&tid, nullptr, run_server_thread,
					(void*) (&client));
			ssl_tid.push_back(tid);
		}
		for (int i = 0; i < ssl_tid.size(); i++) {
			pthread_join(ssl_tid[i], NULL);
		}

	} else {
		printf("Missing flags for start server!\n");
	}
	SSL_CTX_free(ctx);
	close(master_socket);

}
/* EOF - ssl_srv.cpp */
