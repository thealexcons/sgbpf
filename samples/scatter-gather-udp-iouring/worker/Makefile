
all: worker worker_multipacket worker_vector

worker: worker.c
	gcc $^ -o $@

worker_multipacket: worker_multipacket.c
	gcc $^ -o $@

worker_vector: worker_vector.c
	gcc $^ -o $@

clean:
	rm -f worker worker_multipacket worker_vector