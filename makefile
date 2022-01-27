LDLIBS += -lpcap

all: airodump

pcap-test: airodump.cpp

clean:
	rm -f airodump *.o
