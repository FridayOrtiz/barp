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
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
    (void *)1;
static int (*bpf_map_update_elem)(void *map, void *key, void *value, unsigned long long flags) =
    (void *)2;

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

struct arphdr {
    __be16 ar_hrd;                /* format of hardware address	*/
    __be16 ar_pro;                /* format of protocol address	*/
    unsigned char ar_hln;                /* length of hardware address	*/
    unsigned char ar_pln;                /* length of protocol address	*/
    __be16 ar_op;                /* ARP opcode (command)		*/
};
struct arp_body {
        unsigned char	ar_sha[ETH_ALEN];	/* sender hardware address	*/
        unsigned char	ar_sip[4];		/* sender IP address		*/
        unsigned char	ar_tha[ETH_ALEN];	/* target hardware address	*/
        unsigned char	ar_tip[4];		/* target IP address		*/
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

struct sent {
    unsigned char message[ETH_ALEN];
    unsigned char term;
};

struct bpf_map_def arp_filter_events __attribute__((section("maps/arp_filter_events"), used))  = {
        .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(u32),
        .max_entries = 32,
        .map_flags = 0,
        .id = 0,
        .pinning = 0,
};

struct bpf_map_def msg_ctr __attribute__((section("maps/msg_ctr"), used)) = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 1,
	.map_flags = 0,
	.id = 0,
	.pinning = 0,
};

struct bpf_map_def msg_array __attribute__((section("maps/msg_array"), used)) = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 32,
	.map_flags = 0,
	.id = 0,
	.pinning = 0,
};

__attribute__((section("classifier/arp_filter"), used)) int arp_filter(struct __sk_buff *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if ((void*)eth + sizeof(*eth) <= data_end && eth->h_proto == htons(ETH_P_ARP)) {
		struct arphdr *arp = data + sizeof(*eth);
		if ((void*)arp + sizeof(*arp) <= data_end) {
			struct arp_body *bdy = data + sizeof(*eth) + sizeof(*arp);
			if ((void*)bdy + sizeof(*bdy) <= data_end) {
				u32 key = 0;
				u32 *idx = bpf_map_lookup_elem(&msg_ctr, &key);
				if (idx) {
					if (*idx >= 32) {
						*idx = key;
					}
					u64 *msg = bpf_map_lookup_elem(&msg_array, idx);

					if (msg) {
						char * bytes = (char *)msg;
						bdy->ar_tha[0] = *bytes;
						bdy->ar_tha[1] = *(bytes + 1);
						bdy->ar_tha[2] = *(bytes + 2);
						bdy->ar_tha[3] = *(bytes + 3);
						bdy->ar_tha[4] = *(bytes + 4);
						bdy->ar_tha[5] = *(bytes + 5);
						struct sent snt = {
							.message = {
								*bytes,
								*(bytes + 1),
								*(bytes + 2),
								*(bytes + 3),
								*(bytes + 4),
								*(bytes + 5)
							},
							.term = '\0',
						};
						bpf_perf_event_output(
							ctx,
							&arp_filter_events,
							bpf_get_smp_processor_id(),
							&snt,
							sizeof(snt)
						);
						(*idx) += 1;
						bpf_map_update_elem(&msg_ctr, &key, idx, BPF_ANY);
					}
				} else {
					bpf_map_update_elem(&msg_ctr, &key, &key, BPF_ANY);
				}
			}
		}
	}

	return 0;
}

char _license[] __attribute__((section("license"), used)) = "Dual MIT/GPL";
uint32_t _version __attribute__((section("version"), used)) = 0xFFFFFFFE;
