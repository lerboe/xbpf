#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct args {
    int a;
    int b;
    int sum;
};

SEC("syscall")
int add(struct args *args) {
    if (args->a < 0 || args->b < 0) {
        return 1;
    }

    args->sum = args->a + args->b;
    return 0;
}
