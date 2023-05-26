
all: worker worker_multipacket worker_vector worker_scalar

worker: worker.c
	gcc -O2 -g $^ -o $@ -lpthread

worker_multipacket: worker_multipacket.c
	gcc -O2 -g $^ -o $@ -lpthread

worker_vector: worker_vector.c
	gcc -O2 -g $^ -o $@ -lpthread

worker_scalar: worker_scalar.c
	gcc -O2 -g $^ -o $@ -lpthread


clean:
	rm -f worker worker_multipacket worker_vector worker_scalar