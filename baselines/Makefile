
CC = g++
CFLAGS = -std=c++17 -g -O2 -Wall

all: naive event async

naive: naive_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

naive_one_sk: naive_one_sk_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

event: event_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@

async: async_sg.cpp
	$(CC) $(CFLAGS) $^ -o $@ -luring

clean:
	rm -f naive naive_one_sk event async