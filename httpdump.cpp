// HttpDump.cpp: 定义应用程序的入口点。
//
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>
#include <iostream>
#include <set>
#include <chrono>
#include <tuple>
#include "pcap.h"

using namespace std;

// 以太网帧头部结构
struct ether_header
{
	uint8_t ether_dhost[6]; // 目的 MAC 地址
	uint8_t ether_shost[6]; // 源 MAC 地址
	uint16_t ether_type;	// 上层协议类型
};

// IP 头部结构
struct ip_header
{
	uint8_t ip_vhl;	  // 版本和头部长度
	uint8_t ip_tos;	  // 服务类型
	uint16_t ip_len;  // 总长度
	uint16_t ip_id;	  // 标识
	uint16_t ip_off;  // 分片偏移
	uint8_t ip_ttl;	  // 生存时间
	uint8_t ip_proto; // 上层协议类型
	uint16_t ip_sum;  // 校验和
	in_addr ip_src;	  // 源 IP 地址
	in_addr ip_dst;	  // 目的 IP 地址
};

// TCP 头部结构
struct tcp_header
{
	uint16_t th_sport; // 源端口
	uint16_t th_dport; // 目的端口
	uint32_t th_seq;   // 序列号
	uint32_t th_ack;   // 确认号
	uint8_t th_offx2;  // 数据偏移和保留位
	uint8_t th_flags;  // 标志位
	uint16_t th_win;   // 窗口大小
	uint16_t th_sum;   // 校验和
	uint16_t th_urp;   // 紧急指针
};

/* prototype of the packet handler */
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);

vector<string> filters;
bool verbose = false;
int link_type;
int filter_port = 0;
string filter_host;
string filter_method;
string filter_path;
string filter_precise_path;
bool any_interface = false;

void print_help()
{
	cerr << "httpdump [-v] [-a] [-P <port>] [-H <host>] [-m <method>] [-p|-pp <path>] [-g <any text filter>]" << endl;
	exit(0);
}

void parse_args(int argc, char **argv)
{
	for (size_t i = 1; i < argc; i++)
	{
		// help
		if (strcmp("-h", argv[i]) == 0)
		{
			print_help();
		}
		// verbose
		if (strcmp("-v", argv[i]) == 0)
		{
			verbose = true;
			continue;
		}
		// all interface
		if (strcmp("-a", argv[i]) == 0)
		{
			any_interface = true;
			continue;
		}
		// port
		if (strcmp("-P", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filter_port = atoi(argv[++i]);
			continue;
		}
		// host
		if (strcmp("-H", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filter_host = argv[++i];
			continue;
		}
		// method
		if (strcmp("-m", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filter_method = argv[++i];
			continue;
		}
		// path
		if (strcmp("-p", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filter_path = argv[++i];
			continue;
		}
		// precise path
		if (strcmp("-pp", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filter_precise_path = argv[++i];
			continue;
		}
		// any text filter
		if (strcmp("-g", argv[i]) == 0)
		{
			if (i + 1 == argc)
				print_help();
			filters.push_back(argv[++i]);
			continue;
		}
		print_help();
	}
}

int main(int argc, char **argv)
{
	parse_args(argc, argv);
#ifdef _WIN32
#pragma comment(lib, "ws2_32.lib")
	SetConsoleOutputCP(CP_UTF8);
#endif
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	if (any_interface)
	{
		bool find_any = false;
		for (d = alldevs; d; d = d->next)
			if (strcmp("any", d->name) == 0)
			{
				find_any = true;
				break;
			}
		if (!find_any)
		{
			cerr << "Not found 'any' interface" << endl;
			pcap_freealldevs(alldevs);
			return 1;
		}
	}
	else
	{
		/* Print the list */
		for (d = alldevs; d; d = d->next)
		{
			fprintf(stderr, "%d. %s", ++i, d->name);
			if (d->description)
				fprintf(stderr, " (%s)\n", d->description);
			else
				fprintf(stderr, " (No description available)\n");
		}

		if (i == 0)
		{
			fprintf(stderr, "\nNo interfaces found! Make sure Npcap is installed.\n");
			return -1;
		}

		fprintf(stderr, "Enter the interface number (1-%d):", i);
		cin >> inum;

		if (inum < 1 || inum > i)
		{
			fprintf(stderr, "\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		/* Jump to the selected adapter */
		for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++)
			;
	}

	/* Open the device */
	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name, // name of the device
								   65536,	// portion of the packet to capture.
								   // 65536 grants that the whole packet will be captured on all the MACs.
								   1,	  // promiscuous mode (nonzero means promiscuous)
								   1000,  // read timeout
								   errbuf // error buffer
								   )) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	fprintf(stderr, "listening on %s...\n", d->name);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	link_type = pcap_datalink(adhandle);

	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);
	return 0;
}

set<tuple<string, uint16_t, string, uint16_t>> monitor_tuples;

bool starts_with(const char *str, const char *prefix)
{
	size_t len_prefix = strlen(prefix);
	size_t len_str = strlen(str);

	// 如果str比prefix短，肯定不匹配
	if (len_str < len_prefix)
	{
		return false;
	}

	// 比较前缀部分
	return strncmp(str, prefix, len_prefix) == 0;
}

bool is_http_request(string &http_str)
{
	return starts_with(http_str.c_str(), "GET ") || starts_with(http_str.c_str(), "POST ") || starts_with(http_str.c_str(), "PUT ") || starts_with(http_str.c_str(), "PATCH ") || starts_with(http_str.c_str(), "DELETE ") || starts_with(http_str.c_str(), "HEAD ") || starts_with(http_str.c_str(), "OPTIONS ");
}

bool is_http_response(string &http_str)
{
	return starts_with(http_str.c_str(), "HTTP/");
}

bool filter_header(string &header_str)
{
	size_t left = 0, right = 0;

	right = header_str.find(' ', left);
	if (right == string::npos)
		return false;
	string method = header_str.substr(left, right - left);

	left = right + 1;
	right = header_str.find(' ', left);
	if (right == string::npos)
		return false;
	string path = header_str.substr(left, right - left);

	left = right + 1;
	right = header_str.find("Host: ", left);
	if (right == string::npos)
		return false;
	left = right + 6;
	right = header_str.find("\r\n", left);
	if (right == string::npos)
		return false;
	string host = header_str.substr(left, right - left);

	if (!filter_host.empty() && filter_host != host)
		return false;
	if (!filter_method.empty() && filter_method != method)
		return false;
	if (!filter_precise_path.empty() && filter_precise_path != path)
		return false;
	if (!filter_path.empty() && path.find(filter_path) == string::npos)
		return false;
	if (!filters.empty())
		for (auto &&filter : filters)
			if (header_str.find(filter) == string::npos)
				return false;

	return true;
}

char *now()
{
	static char time_str[30];

	auto timestamp_ms = chrono::duration_cast<chrono::milliseconds>(chrono::system_clock::now().time_since_epoch()).count();
	time_t timestamp_s = timestamp_ms / 1000;
	int ms = timestamp_ms % 1000;
	auto tm_p = localtime(&timestamp_s);

	size_t n = strftime(time_str, sizeof time_str, "%Y-%m-%d %H:%M:%S", tm_p);
	sprintf(time_str + n, ".%03d", ms);

	return time_str;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
	// 以太网头+IP头+TCP头
	if (header->caplen < 14 + 20 + 20)
	{
		return;
	}
	// 解析 IP 头部
	const struct ip_header *ip_header;
	// Linux "any" link type头16字节；以太网头14字节
	if (link_type == DLT_LINUX_SLL)
	{
		ip_header = (struct ip_header *)(pkt_data + 16);
	}
	else
	{
		ip_header = (struct ip_header *)(pkt_data + 14);
	}

	// 检查 IP 协议类型是否为 TCP
	if (ip_header->ip_proto == IPPROTO_TCP)
	{
		// 解析 TCP 头部
		const struct tcp_header *tcp_header = (struct tcp_header *)((char *)ip_header + (ip_header->ip_vhl & 0x0F) * 4);

		string src_ip = string(inet_ntoa(ip_header->ip_src));
		string dst_ip = string(inet_ntoa(ip_header->ip_dst));
		uint16_t src_port = ntohs(tcp_header->th_sport);
		uint16_t dst_port = ntohs(tcp_header->th_dport);

		if (filter_port != 0 && filter_port != src_port && filter_port != dst_port)
			return;

		uint16_t ip_len = ntohs(ip_header->ip_len);
		uint8_t tcp_head_len = tcp_header->th_offx2 >> 2;
		uint16_t tcp_data_len = ip_len - ((ip_header->ip_vhl & 0xf) << 2) - tcp_head_len;
		uint32_t seq = ntohl(tcp_header->th_seq);

		if (tcp_data_len == 0)
		{
			return;
		}
		auto http_str = string((char *)tcp_header + tcp_head_len, tcp_data_len);
		auto tuple = make_tuple(src_ip, src_port, dst_ip, dst_port);
		if (is_http_request(http_str))
		{
			if (!filter_header(http_str))
				return;

			auto tuple_re = make_tuple(dst_ip, dst_port, src_ip, src_port);
			monitor_tuples.insert(tuple);
			monitor_tuples.insert(tuple_re);
			if (verbose)
			{
				cout << '\n'
					 << "\033[36m" << now()
					 << " \033[32m" << src_ip << "\033[0m:\033[33m" << src_port << "\033[0m -> \033[32m" << dst_ip << "\033[0m:\033[33m" << dst_port << "\033[0m";
			}
			cout << '\n'
				 << http_str << flush;
		}
		else if (monitor_tuples.find(tuple) != monitor_tuples.end())
		{
			if (verbose)
			{
				cout << '\n'
					 << "\033[36m" << now()
					 << " \033[32m" << src_ip << "\033[0m:\033[33m" << src_port << "\033[0m -> \033[32m" << dst_ip << "\033[0m:\033[33m" << dst_port
					 << "\033[0m" << '\n';
			}
			else if (is_http_response(http_str))
				cout << '\n';
			cout << http_str << flush;
		}
	}
}
