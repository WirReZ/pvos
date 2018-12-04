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

/* define HOME to be dir for key and cert files... */
#define HOME "./keys/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "cert.crt"
#define KEYF  HOME  "key.pem"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

struct zprava {
	long typ; // musi byt urcet typ zpravy
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
		this->reader = new SSLReadLine(fd, ssl, 10);
		this->ssl = ssl;
	}
};
void sigpipe_handler(int num, siginfo_t* info, void* data) {
}

int queue = msgget(0XABCDABCD, 0660 | IPC_CREAT);

void run_server_fork(int* sck, SSL_CTX* ctx) {

	int client_socket;
	int err;

	zprava zp;
	client_socket = *sck;
	CHK_ERR(client_socket, "accept");

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
		sprintf(sendbuf, "%ld %ld %ld\n", num_lines, sum,
				total_queue + total_bytes);
		num_lines++;

		/*int len = msgrcv(queue, &zp, sizeof(zp.buf), 1, IPC_NOWAIT);
		 if (errno != ENOMSG) {
		 zp.buf[len] = 0;

		 sscanf(zp.buf, "%ld\n", &total_queue);
		 zp.typ = 1;
		 total_queue += total_bytes;
		 total_bytes = 0;
		 sprintf(zp.buf, "%ld\n", total_queue);

		 msgsnd(queue, &zp, strlen(zp.buf), getpid());
		 }
		 */
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
	long int total_queue = 0;
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
		sprintf(sendbuf, "%ld %ld %ld\n", num_lines, sum,
				total_queue + total_bytes);
		num_lines++;

		err = SSL_write(client.ssl, sendbuf, strlen(sendbuf));
		CHK_SSL(err);
		if (err == -1) {
			break;
		}

	}

	close(client.fd);
	SSL_free(client.ssl);
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

	//getopt
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
			//sscanf(optarg, "%d", &process_number);
			printf("Server starting with process method\n");
			break;
		case 't':
			thread_flag = 1;
			//sscanf(optarg, "%d", &thread_number);
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

	memset(&sa_serv, '\0', sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = INADDR_ANY;
	sa_serv.sin_port = htons(1111); /* Server Port number */

	err = bind(master_socket, (struct sockaddr*) &sa_serv, sizeof(sa_serv));
	CHK_ERR(err, "bind");

	/* Receive a TCP connection. */
	err = listen(master_socket, 5);
	CHK_ERR(err, "listen");

	// SELECT SECITON !!!!
	if (select_flag == 1) {
		struct sigaction action { };
		action.sa_sigaction = sigpipe_handler;
		action.sa_flags = SA_SIGINFO | SA_RESTART;
		sigemptyset(&action.sa_mask);
		sigaction(SIGPIPE, &action, nullptr);

		std::vector<Client> clients;

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
			}

			for (int i = 0; i < clients.size(); i++) {
				if (FD_ISSET(clients[i].fd, &waiting_set)) {

					err = clients[i].reader->readline();
					if (err <= 0) {
						printf("Client %d disconnected !\n", i);
						close(clients[i].fd);
						SSL_free(clients[i].ssl);

						clients.erase(clients.begin() + i);
						//break;
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

					err = SSL_write(clients[i].ssl, sendbuf, strlen(sendbuf));

					CHK_SSL(err);

				}
			}
		}
	} else if (process_flag == 1) {
		zprava zp;
		zp.typ = 1;
		sprintf(zp.buf, "0");
		msgsnd(queue, &zp, strlen(zp.buf), 0);

		while (1) {
			client_len = sizeof(sa_cli);
			int client_socket = accept(master_socket,
					(struct sockaddr*) &sa_cli, &client_len);
			CHK_ERR(client_socket, "accept");

			if (fork() == 0) {
				printf("PID: %d => Connection from %s, port %d\n", getpid(),
						inet_ntoa(sa_cli.sin_addr), sa_cli.sin_port);
				run_server_fork(&client_socket, ctx);
				exit(0);
			}
			int pid;
			while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
				printf("Server %d finished.\n", pid);
		}

	} else if (process_flag == 0 && thread_flag == 1) {
		std::vector<pthread_t> ssl_tid;
		int i = 0;
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
