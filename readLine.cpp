#include "readLine.h"

readLine::readLine(int fd, int tim_out) {
	this->line = 0;
	this->charCounter = 0;
	this->maxBufferLen = 1024;
	this->buffer = (char*) malloc(this->maxBufferLen * sizeof(char));
	this->internalBuffer = (char*) malloc(this->maxBufferLen * sizeof(char));
	this->fd = fd;

	FD_ZERO(&this->readset);
	FD_SET(fd, &this->readset);

	timeout.tv_sec = 0;
	timeout.tv_usec = tim_out * 1000 * 1000;

}
int readLine::readline() {
	while (1) {
		int ret = select(this->fd + 1, &this->readset, nullptr, nullptr,
				&this->timeout);
		if (ret > 0 && FD_ISSET(this->fd, &this->readset)) {
			int available_spaces = this->maxBufferLen - this->charCounter;
			if (available_spaces <= 0) {
				maxBufferLen *= 2;
				this->buffer = (char*) realloc(this->buffer,
						maxBufferLen * sizeof(char));
				this->internalBuffer = (char*) realloc(this->internalBuffer,
						maxBufferLen * sizeof(char));
				available_spaces = this->maxBufferLen - this->charCounter;
			}

			int len = read(this->fd, this->internalBuffer + this->charCounter,
					available_spaces);
			if (len > 0) {
				this->charCounter += len;
				this->internalBuffer[this->charCounter] = '\0';

				char* new_line = strchr(this->internalBuffer, '\n');
				if (new_line != NULL) {
					int position_new_line = new_line - this->internalBuffer + 1;
					memcpy(this->buffer, this->internalBuffer,
							position_new_line);
					this->buffer[position_new_line] = '\0';

					charCounter -= position_new_line;
					memcpy(this->internalBuffer,
							this->internalBuffer + position_new_line,
							charCounter);
					return position_new_line;
				}

			} else
				return 0;
		} else
			return -1; // timeout

	}
}
char* readLine::toString() {
	return this->buffer;
}
readLine::~readLine() {
	free(this->internalBuffer);
	free(this->buffer);
}
/*  SSL READER */
SSLReadLine::SSLReadLine(int sd, SSL* ssl, int tim_out) :
		readLine(sd, tim_out) {
	this->ssl = ssl;
}
int SSLReadLine::readline() {

	while (1) {
		int ret = select(this->fd + 1, &this->readset, nullptr, nullptr,
				&this->timeout);

		if (ret > 0 && FD_ISSET(this->fd, &this->readset)) {

			int available_spaces = this->maxBufferLen - this->charCounter;
			if (available_spaces <= 0) {

				maxBufferLen *= 2;
				this->buffer = (char*) realloc(this->buffer,
						maxBufferLen * sizeof(char));
				this->internalBuffer = (char*) realloc(this->internalBuffer,
						maxBufferLen * sizeof(char));
				available_spaces = this->maxBufferLen - this->charCounter;
			}

			int len = SSL_read(this->ssl,
					this->internalBuffer + this->charCounter, available_spaces);

			if (len > 0) {
				this->charCounter += len;
				this->internalBuffer[this->charCounter] = '\0';

				char * new_line = strchr(this->internalBuffer, '\n'); // Check if there is a new line if yes then return
				if (new_line != NULL) {
					int position_new_line = new_line - this->internalBuffer + 1;
					memcpy(this->buffer, this->internalBuffer,
							position_new_line);
					this->buffer[position_new_line] = '\0';

					charCounter -= position_new_line;
					memcpy(this->internalBuffer,
							this->internalBuffer + position_new_line,
							charCounter);
					return position_new_line;

				}
			} else
				return 0;
		} else
			return -1; // timeout

	}
}
SSLReadLine::~SSLReadLine() {

}
