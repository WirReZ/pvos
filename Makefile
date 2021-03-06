TARGET1=ssl_cli
TARGET2=ssl_srv
TARGETS=$(TARGET1) $(TARGET2)

all: $(TARGETS)

readLine.o: readLine.cpp
	g++ -std=c++11 -O -c readLine.cpp -g

$(TARGET1): $(TARGET1).cpp readLine.cpp
	g++ -std=c++11 -pthread $^ -o $@ -lssl -lcrypto -g 
	
$(TARGET2): $(TARGET2).cpp readLine.cpp
	g++ -std=c++11 -pthread $^ -o $@ -lssl -lcrypto -g
	
clean: 
	rm -rf $(TARGETS)