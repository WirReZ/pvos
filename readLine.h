#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>
#include <string.h>
#include <algorithm>

#include <openssl/ssl.h>

class readLine{
protected:
	char *buffer;
	char *internalBuffer;
	int line;
	int charCounter;
	int maxBufferLen;
	int fd;
	timeval timeout{};
	fd_set readset{};
public:
	readLine(int,int);
	~readLine();
	int readline();
	char* toString();

};

class SSLReadLine : public readLine{
private:
	SSL* ssl = NULL;
public:
	SSLReadLine(int fd, SSL* ssl, int tim_out);
	virtual int readline();
	virtual ~SSLReadLine();
};
