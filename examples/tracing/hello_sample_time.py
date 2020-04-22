#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT with Sample time collection enabled.

from bcc import BPF
from bcc.utils import printb
import ctypes as ct

SAMPLE_FLAGS_USE_RAW_DATA = 1
SAMPLE_FLAGS_RAW_TIME = 2

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int hello(struct pt_regs *ctx) {
    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")

# header
print("%-18s %-18s %-16s %-6s %s" % ("BPF RAW TIME", "TIME(s)", "COMM", "PID", "MESSAGE"))

# process event
start = 0
fields = [
        ("__raw_bpf_ts", ct.c_ulong),
        ("__raw_bpf_size", ct.c_int),
    ]
wrapper_class = type('', (ct.Structure,), {'_fields_': fields})

def print_event(cpu, data, size):

    wrapper_obj = ct.cast(data, ct.POINTER(wrapper_class)).contents
    data += ct.sizeof(ct.c_ulong) + ct.sizeof(ct.c_int)

    event = b["events"].event(data)

    event.__raw_bpf_ts = wrapper_obj.__raw_bpf_ts
    printb(b"%-18d %-18d %-16s %-6d %s" % (event.__raw_bpf_ts, event.ts, event.comm, event.pid,
    b"Hello, perf_output!"))
flags = SAMPLE_FLAGS_USE_RAW_DATA | SAMPLE_FLAGS_RAW_TIME
# loop with callback to print_event
b["events"].open_perf_buffer(print_event, flags=flags)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
