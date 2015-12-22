#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>


static struct nf_hook_ops netfilter_ops;
struct sk_buff *sock_buff;

unsigned long inet_aton(const char*);
unsigned int main_hook(unsigned int hooknum,
						struct sk_buff *skb,
						const struct net_device *in,
						const struct net_device *out,
						int (*okfn)(struct sk_buff*))
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned long saddr = 0, daddr = 0;
	struct tcphdr *tcph = (struct tcphdr*)tcp_hdr(skb);
	unsigned long cse = inet_aton("164.125.7.52");	//정컴홈페이지
	saddr = iph->saddr;
	daddr = iph->daddr;

	if(saddr == cse){return NF_DROP;}	//패킷 Drop


	return NF_ACCEPT;
}

int init_module()
{
	netfilter_ops.hook = main_hook;
	netfilter_ops.pf = PF_INET;
	netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops.priority = 1; 
	nf_register_hook(&netfilter_ops);	//모듈 등록
	printk("<1>----drop module start!!\n");
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops);	//모듈 해제
	printk("<1>-----end!!----\n");
}

unsigned long  inet_aton(const char * str)
{
	unsigned long result = 0;
	unsigned int iaddr[4] = {0,};
	unsigned char addr[4] = {0,};

	int i;
	sscanf(str,"%d.%d.%d.%d ",iaddr,iaddr+1,iaddr+2,iaddr+3);

	for(i = 0 ; i < 4 ; i++)
	{
		addr[i] = (char)iaddr[i];
	}
	for(i = 3 ; i > 0 ; i--)
	{
		result |= addr[i];
		result <<= 8;
	}
	result |= addr[0];
	
	return result;
}
