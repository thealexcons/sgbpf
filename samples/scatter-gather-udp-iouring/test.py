import os, fcntl

#Run with: sudo python3 -m pytest test.py

# Define the path to the filesystem pipe
pipe_path = "/sys/kernel/debug/tracing/trace_pipe"

# Open the pipe for reading
try:
    pipe_fd = os.open(pipe_path, os.O_RDONLY)
    flags = fcntl.fcntl(pipe_fd, fcntl.F_GETFL)
    flags |= os.O_NONBLOCK
    fcntl.fcntl(pipe_fd, fcntl.F_SETFL, flags)
except PermissionError:
    print("!!! Run test with sudo in order to read the kernel trace pipe !!!")
    exit(1)

# Read the workers file
workers = []
with open("worker/workers.cfg", "r") as f:
    for l in f.readlines():
        workers.append(l[:-1])

def read_trace():
    # Read data from the pipe
    try:
        data = os.read(pipe_fd, 4096)
    except BlockingIOError:
        return []

    out = []
    lines = data.decode().splitlines()
    for line in lines:
        ll = line.split("bpf_trace_printk: ")
        if len(ll) > 1:
            out.append(ll[1])
    return out

# def str_i

def test_scatter_message_sent():
    lines = read_trace()
    combined = '\t'.join(lines)
    assert "Got SCATTER request" in lines
    for worker_str in workers:
        assert worker_str in combined
    assert "Finished SCATTER request" in lines
