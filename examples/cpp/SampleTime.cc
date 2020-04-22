/*
 * Copyright (c) Facebook, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License")
 */

#include <signal.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <string>

#include "BPF.h"
#include "perf_sample_config.h"

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>


struct event_t {
  int pid;
  char name[16];
  u64 ts;
};

BPF_PERF_OUTPUT(events);

int on_sys_clone(struct pt_regs *ctx) {
    struct event_t event = {};

    event.pid = bpf_get_current_pid_tgid();
    event.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&event.name, sizeof(event.name));

    events.perf_submit(ctx, &event, sizeof(event));

    return 1;
}
)";

// definer wrapper struci
struct perf_sample {
  uint64_t ts;
  uint32_t size;
  char data[0];
};

// Define the same struct to use in user space.
struct event_t {
  int pid;
  char name[16];
  uint64_t ts;
};

std::function<void(int)> shutdown_handler;

void signal_handler(int s) { shutdown_handler(s); }

bool ended = false;

void handle_output(void* cb_cookie, void* data, int data_size) {
  auto sample = static_cast<perf_sample*>(data);
  auto event = static_cast<event_t*>((void*)sample->data);

  std::cout << "Sample Event Timestamp:" << sample->ts
            << " BPF TimeStamp:" << event->ts << " PID " << event->pid << " ("
            << event->name << ") "
            << "\n";
}

int main() {
  ebpf::BPF bpf;
  std::cout << "bpf_setup_event --> init" << std::endl;
  auto init_res = bpf.init(BPF_PROGRAM);
  std::cout << "bpf_setup_event --> after init" << std::endl;

  if (init_res.code() != 0) {
    std::cerr << init_res.msg() << std::endl;
    return 1;
  }

  std::string clone_fnname = bpf.get_syscall_fnname("clone");

  auto attach_res = bpf.attach_kprobe(clone_fnname, "on_sys_clone");
  if (attach_res.code() != 0) {
    std::cerr << attach_res.msg() << std::endl;
    return 1;
  }

  auto flags = SAMPLE_FLAGS_USE_RAW_DATA | SAMPLE_FLAGS_RAW_TIME;
  auto open_res =
      bpf.open_perf_buffer("events", &handle_output, nullptr, nullptr,
                           DEFAULT_PERF_BUFFER_PAGE_CNT, flags);
  if (open_res.code() != 0) {
    std::cerr << open_res.msg() << std::endl;
    return 1;
  }

  shutdown_handler = [&](int s) {
    std::cerr << "Terminating..." << std::endl;
    exit(0);
  };

  signal(SIGINT, signal_handler);

  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  auto perf_buffer = bpf.get_perf_buffer("events");
  if (perf_buffer)
    while (true)
      // 100ms timeout
      perf_buffer->poll(100);
  return 0;
}
