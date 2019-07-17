all : pcap_test

pcap_test: packet.o main.o
	g++ -g -o pcap_test packet.o main.o -lpcap

packet.o: packet.h packet.cpp
	g++ -g -c -o packet.o packet.cpp

main.o: packet.h main.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -f pcap_test
	rm -f *.o

