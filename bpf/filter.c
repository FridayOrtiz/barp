#define KBUILD_MODNAME "barp"
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#include <linux/kconfig.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_ether.h>
//#include <uapi/linux/if_arp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

static unsigned long long (*bpf_get_smp_processor_id)(void) =
    (void *)8;
static int (*bpf_perf_event_output)(void *ctx, void *map, unsigned long long flags, void *data, int size) =
    (void *)25;

struct arphdr {
	__be16		ar_hrd;		/* format of hardware address	*/
	__be16		ar_pro;		/* format of protocol address	*/
	unsigned char	ar_hln;		/* length of hardware address	*/
	unsigned char	ar_pln;		/* length of protocol address	*/
	__be16		ar_op;		/* ARP opcode (command)		*/
};

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
    unsigned int id;
    unsigned int pinning;
};

struct bpf_map_def arp_filter_events __attribute__((section("maps/arp_filter_events"), used))  = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 1024,
        .map_flags = 0,
        .id = 0,
        .pinning = 0,
};

__attribute__((section("classifier/arp_filter"), used)) int arp_filter(struct __sk_buff *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) <= data_end) {
		struct arphdr *arp = data + sizeof(*eth);
		if ((void*)arp + sizeof(*arp) <= data_end) {
			struct arphdr my_arp = *arp;
			bpf_perf_event_output(
					ctx, 
					&arp_filter_events, 
					bpf_get_smp_processor_id(),
					&my_arp,
					sizeof(my_arp)
			);
		}
	}

	return 0;
}

char _license[] __attribute__((section("license"), used)) = "Dual MIT/GPL";
uint32_t _version __attribute__((section("version"), used)) = 0xFFFFFFFE;
