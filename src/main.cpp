#include <boost/program_options.hpp>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <endian.h>
#include <sstream>
#include <iostream>
#include <ctime>

namespace po = boost::program_options;

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET   14

/* Ethernet header */
struct sniff_ethernet 
{
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type; 
};

/* IP header */
struct sniff_ip 
{
	uint8_t ip_vhl;			/* version << 4 | header length >> 2 */
	uint8_t ip_tos;			/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;			/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t ip_ttl;			/* time to live */
	uint8_t ip_p;			/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

/* UDP header */
struct sniff_udp
{
	uint16_t port_src;		/* source port */
	uint16_t port_dst;		/* destination port */
	uint16_t dtg_length;	/* datagramm length */
	uint16_t checksum;		/* checksum */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f) 

void
handle_packet(u_char *user, const struct pcap_pkthdr* h, const u_char* packet) 
{
	sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	uint size_ip = IP_HL(ip) * 4;
	sniff_udp* udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

	// convert in_addr struct to string representation
	char str_ip_dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip->ip_dst, str_ip_dst, INET_ADDRSTRLEN);

	// convert big-endian to host representation
	uint16_t port_dst = be16toh(udp->port_dst);

	// calculate payload size
	int payload_size = h->len - (SIZE_ETHERNET + size_ip + 2 * sizeof(uint32_t));

	time_t t = h->ts.tv_sec;
	tm* u = localtime(&t);

	std::stringstream date;
	date << u->tm_mday << "." << 1 + u->tm_mon << "." << u->tm_year + 1900;

	std::stringstream time;
	time << u->tm_hour << ":" << u->tm_min << ":" << u->tm_sec << ":" << h->ts.tv_usec;

	std::cout.setf(std::ios::left);
	std::cout.width(13);
	std::cout << date.str();

	std::cout.width(19);
	std::cout << time.str();

	std::cout.width(19);
	std::cout << str_ip_dst;

	std::cout.width(10);
	std::cout << port_dst;

	std::cout << payload_size << std::endl;
}

int 
main(int argc, const char* argv[])
{
	std::string port_dst;
	std::string ip_address_dst;
	std::string pcap_file_path;

	// configure command line options using boost::program_options
	po::options_description desc("Allowed options");
	desc.add_options()
    	("help,h", "Produce help message")
    	("address,a", po::value<std::string>(&ip_address_dst)->default_value(""), "Destination address to filter")
    	("port,p", po::value<std::string>(&port_dst)->default_value(""), "Destination port to filter")
    	("input-file", po::value<std::string>(&pcap_file_path), "Input PCAP file")
	;

	po::positional_options_description p;
	p.add("input-file", -1);

	po::variables_map vm;
	po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
	po::notify(vm);    

	if (vm.count("help")) 
	{
	    std::cout << desc << std::endl;
	    return 1;
	}

	char error[PCAP_ERRBUF_SIZE];
	
	pcap_t* pcap_file = pcap_open_offline(pcap_file_path.c_str(), error);
	if(pcap_file == nullptr)
	{
		std::cerr << error << std::endl;
		return 1;
	}

	std::string filter_config = "udp";
	if(port_dst != "")
		filter_config += " dst port " + port_dst; 
	if(ip_address_dst != "")
		filter_config += " and (ip dst host " + ip_address_dst + ")";

	bpf_program fp;
	
	if(pcap_compile(pcap_file, &fp, filter_config.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
		std::cerr << "Error calling pcap_compile" << std::endl;
		pcap_close(pcap_file);
		return 1;
	} 

	if(pcap_setfilter(pcap_file, &fp) == -1) {
		std::cerr << "Error setting filter" << std::endl;
		pcap_close(pcap_file);
		return 1;
	}

	std::cout.setf(std::ios::left);
	std::cout.width(13);
	std::cout << "DATE";

	std::cout.width(19);
	std::cout << "TIME";

	std::cout.width(19);
	std::cout << "DST_IP";

	std::cout.width(10);
	std::cout << "DST_PORT";

	std::cout << "PAYLOAD_SIZE" << std::endl;

	int result = pcap_loop(pcap_file, -1, handle_packet, NULL); 
	if(result == -1)
		std::cerr << "Error occurs during package processing with pcap_loop" << std::endl;
	else if(result == -2)
		std::cerr << "Loop terminated due to call to pcap_breakloop" << std::endl;

	pcap_close(pcap_file);
	return 0;
}