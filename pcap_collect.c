/*
 * pcap_collect.c
 *
 *  Created on: Feb 22, 2013
 *      Author: reskim
 */



#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pcap.h>
#include <time.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <math.h>
#include <complex.h>
#include <mysql/mysql.h>
#include <openssl/md5.h>
#include <unistd.h>
#include <errno.h>

#define FILENAME_MAX 256
#define ETHERNET_HEADER_SIZE 14

/********************************
 * Structs
 *******************************/

//Argparse Struct
struct {
    int argcount;
    char **argvariables;
    char filename[FILENAME_MAX];
    int verbosemode;
}typedef argparse;

/***********************************
 * Struc for one packet within the pcap
 ***********************************/
struct{
	int etherWire;
	int etherSize;
	int ipSize;
	int ipHdrSize;
	int ipLength;
	struct sockaddr_in ipSource;
	struct sockaddr_in ipDestination;
	int tcpSize;
	int tcpHdrSize;
	uint tcpPortSource;
	uint tcpPortDestination;
}typedef packet;

/**********************************
 * Struct that holds information about
 * the entire stream
 **********************************/
typedef struct{
	double etherMean;
	double etherStd;
	double ipMean;
	int etherMin;
	int etherMax;
	double ipHdrMean;
	double ipHdrStd;
	double ipStd;
	int ipMin;
	int ipMax;
	int ipHdrMin;
	int ipHdrMax;
	double tcpMean;
	double tcpHdrMean;
	double tcpStd;
	double tcpHdrStd;
	int tcpMin;
	int tcpMax;
	int tcpHdrMin;
	int tcpHdrMax;
	double q1EtherMean;
	double q2EtherMean;
	double q3EtherMean;
	double q4EtherMean;
	double q1EtherStd;
	double q2EtherStd;
	double q3EtherStd;
	double q4EtherStd;
	int q1EtherMin;
	int q1EtherMax;
	int q2EtherMin;
	int q2EtherMax;
	int q3EtherMin;
	int q3EtherMax;
	int q4EtherMin;
	int q4EtherMax;
	double q1IpMean;
	double q2IpMean;
	double q3IpMean;
	double q4IpMean;
	double q1IpStd;
	double q2IpStd;
	double q3IpStd;
	double q4IpStd;
	int q1IpMin;
	int q1IpMax;
	int q2IpMin;
	int q2IpMax;
	int q3IpMin;
	int q3IpMax;
	int q4IpMin;
	int q4IpMax;
	double q1IpHdrMean;
	double q2IpHdrMean;
	double q3IpHdrMean;
	double q4IpHdrMean;
	double q1IpHdrStd;
	double q2IpHdrStd;
	double q3IpHdrStd;
	double q4IpHdrStd;
	int q1IpHdrMin;
	int q1IpHdrMax;
	int q2IpHdrMin;
	int q2IpHdrMax;
	int q3IpHdrMin;
	int q3IpHdrMax;
	int q4IpHdrMin;
	int q4IpHdrMax;
	double q1TcpMean;
	double q2TcpMean;
	double q3TcpMean;
	double q4TcpMean;
	double q1TcpStd;
	double q2TcpStd;
	double q3TcpStd;
	double q4TcpStd;
	int q1TcpMin;
	int q1TcpMax;
	int q2TcpMin;
	int q2TcpMax;
	int q3TcpMin;
	int q3TcpMax;
	int q4TcpMin;
	int q4TcpMax;
	double q1TcpHdrMean;
	double q2TcpHdrMean;
	double q3TcpHdrMean;
	double q4TcpHdrMean;
	double q1TcpHdrStd;
	double q2TcpHdrStd;
	double q3TcpHdrStd;
	double q4TcpHdrStd;
	int q1TcpHdrMin;
	int q1TcpHdrMax;
	int q2TcpHdrMin;
	int q2TcpHdrMax;
	int q3TcpHdrMin;
	int q3TcpHdrMax;
	int q4TcpHdrMin;
	int q4TcpHdrMax;
}stream;

/***********************************
 * Prototypes
 **********************************/
void displayOutput(int count, int* quartile, packet* packetStream, stream stream);
void f_argparser(int argc, char **argv, argparse* arg_vars);
int countPackets(pcap_t* handle);
void setPackets(pcap_t* handle, packet* packetStream, argparse arguments);
double calcEtherMean(packet* packetStream, int start, int finish);
double calcEtherStd(packet* packetStream, int start, int finish);
double calcIpMean(packet* packetStream, int start, int finish);
double calcIpHdrMean(packet* packetStream, int start, int finish);
double calcTcpMean(packet* packetStream, int start, int finish);
double calcIpMean(packet* packetStream, int start, int finish);
double calcTcpHdrMean(packet* packetStream, int start, int finish);
double calcIpStd(packet* packetStream, int start, int finish);
double calcTcpStd(packet* packetStream, int start, int finish);
void quartileCalc(int count, int* quartile);

double calcIpHdrStd(packet* packetStream, int start, int finish);
double calcTcpHdrStd(packet* packetStream, int start, int finish);

void packetMinMaxEther(packet* packetStream, int* minMax, int start, int finish);
void packetMinMaxIp(packet* packetStream, int* minMax, int start, int finish);
void packetMinMaxIpHdr(packet* packetStream, int* minMax, int start, int finish);
void packetMinMaxTcp(packet* packetStream, int* minMax, int start, int finish);
void packetMinMaxTcpHdr(packet* packetStream, int* minMax, int start, int finish);

void discriminatorCalc(int count, int* quartile, packet* packetStream, stream* stream);
void sortPacketsEther(int count, packet* packetStream);
void sortPacketsIp(int count, packet* packetStream);
void sortPacketsIpHdr(int count, packet* packetStream);
void sortPacketsTcp(int count, packet* packetStream);
void sortPacketsTcpHdr(int count, packet* packetStream);
void verbosePacketOutput(int count, packet* packetStream);
MYSQL* mysqlConnector(MYSQL *mysql);
void calcmd5Sum(FILE* file_name, char* md5sum);
my_ulonglong saveStreamInfo( MYSQL *mysql, char* md5, stream* mainStream, stream *etherStream, stream *ipStream, stream *ipHdrStream, stream *tcpStream, stream *tcpHdrStream );

extern int errno;
/*********************************************
 * Main Function
 * @param argc Number of arguments passed in
 * @param argv Path to file to open, verbose mode on/off
 * @return
 *********************************************/
int main (int argc, char **argv){
	printf("\n\n");
    //Local Pcap Variables
    pcap_t* handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct stat fileStat;
    char md5Sum[MD5_DIGEST_LENGTH*2];

    //Parsing arguments
    argparse arguments;
    f_argparser(argc, argv, &arguments);
    if(arguments.filename[0] != '\0'){
        if(arguments.verbosemode == 1){
          printf("Verbose mode is on!\n");
        }
        printf("Opening file: %s\n\n", arguments.filename);
    }
    else{
        printf("Usage: pcap_collect -v -f [filename]\n");
        return 1;
    }
    //Starting to open pcap file
        if(stat(arguments.filename, &fileStat) < 0){
            printf("File does not exists!\n");
            return 1;
        }
        else{
        	//Calculating MD5 Sum
            FILE* file_MD5;
            file_MD5 = fopen(arguments.filename, "rb");
            calcMd5Sum(file_MD5, md5Sum);
            fclose(file_MD5);
            //Opening a pcap handle
            handle = pcap_open_offline(arguments.filename, errbuf);
        }
        /**********************************
         * Main Operation
         *********************************/
        //Grabbing total count of packets
        int count = countPackets(handle);
        int quartile[4];
        quartileCalc(count, quartile);
        //int temp[2] = {0,0};
        //Allocating array of packets of count #
        packet packetStream[count];
        //Filling out packet array
        setPackets(handle, packetStream, arguments);

        //Struct used to hold stream information
        stream stream, streamEther, streamIp, streamIpHdr, streamTcp, streamTcpHdr;
        memset(&stream, 0, sizeof(stream));
        memset(&streamEther, 0, sizeof(stream));
        memset(&streamIp, 0, sizeof(stream));
        memset(&streamIpHdr, 0, sizeof(stream));
        memset(&streamTcp, 0, sizeof(stream));
        memset(&streamTcpHdr, 0, sizeof(stream));
        //Calculations for Stream
        discriminatorCalc(count, quartile, packetStream, &stream);

        //Sorting Stream
        //Sorting by Ether Size
        packet packetEther[count];
        memcpy(&packetEther, &packetStream, sizeof(packetEther));
        sortPacketsEther(count, packetEther);
        discriminatorCalc(count, quartile, packetEther, &streamEther);
        //Sorting by IP Size
        packet packetIp[count];
        memcpy(&packetIp, &packetStream, sizeof(packetIp));
        sortPacketsEther(count, packetIp);
        discriminatorCalc(count, quartile, packetIp, &streamIp);
        //Sorting by IP Header Size
        packet packetIpHdr[count];
        memcpy(&packetIpHdr, &packetStream, sizeof(packetIpHdr));
        sortPacketsIpHdr(count, packetIpHdr);
        discriminatorCalc(count, quartile, packetIpHdr, &streamIpHdr);
        //Sorting by TCP Size
        packet packetTcp[count];
        memcpy(&packetTcp, &packetStream, sizeof(packetTcp));
        sortPacketsTcp(count, packetTcp);
        discriminatorCalc(count, quartile, packetTcp, &streamTcp);
        //Sorting by TCP Header Size
        packet packetTcpHdr[count];
        memcpy(&packetTcpHdr, &packetStream, sizeof(packetTcpHdr));
        sortPacketsTcpHdr(count, packetTcpHdr);
        discriminatorCalc(count, quartile, packetTcpHdr, &streamTcpHdr);
        /***************
         * Mysql Section
         ***************/
        MYSQL *mysql;
        mysql = mysqlConnector(mysql);
        int mysqlid = saveStreamInfo(mysql, &md5Sum, &stream, &streamEther, &streamIp, &streamIpHdr, &streamTcp, &streamTcpHdr);




        /*****************
         * Printing Output
         ****************/
        printf("\n***MD5SUM***\n");
        printf("%s\n", md5Sum);
        if(arguments.verbosemode == 1){
        	printf("\n***Sorted by Order Received***\n");
        	verbosePacketOutput(count, packetStream);
        	printf("\n***Sorted by Ethernet Size***\n");
        	verbosePacketOutput(count, packetEther);
        	printf("\n***Sorted by IP Size***\n");
        	verbosePacketOutput(count, packetIp);
        	printf("\n***Sorted by IP Header Size***\n");
        	verbosePacketOutput(count, packetIpHdr);
        	printf("\n***Sorted by TCP Size***\n");
        	verbosePacketOutput(count, packetTcp);
        	printf("\n***Sorted by TCP Header Size***\n");
        	verbosePacketOutput(count, packetTcpHdr);
        }
        printf("\n****Summary Order Received****\n");
        displayOutput(count, quartile, packetStream, stream);
        printf("\n****Summary Ether Size****\n");
        displayOutput(count, quartile, packetEther, streamEther);
        printf("\n****Summary IP Size****\n");
        displayOutput(count, quartile, packetIp, streamIp);
        printf("\n****Summary IP Header Size****\n");
        displayOutput(count, quartile, packetIp, streamIpHdr);
        printf("\n****Summary TCP Size****\n");
        displayOutput(count, quartile, packetIp, streamTcp);
        printf("\n****Summary TCP Header Size****\n");
        displayOutput(count, quartile, packetIp, streamTcpHdr);
        printf("\nMysql column ID: %u\n", mysqlid);


        return 0;
}


/**********************************************
 *
 * @param argc Argument count
 * @param argv Arguments for file and verbose mode
 * @param arg_vars Struct to parse
 **********************************************/

    void f_argparser(int argc, char **argv, argparse* arg_vars){
        arg_vars->verbosemode = -1;
        arg_vars->filename[0] = '\0';
        int switchcase = 0;
        opterr = 0;

        while((switchcase = getopt (argc, argv, "vf:")) != -1){
            switch (switchcase){
              case 'v':
                arg_vars->verbosemode = 1;
                break;
              case 'f':
                strncpy( arg_vars->filename, optarg, FILENAME_MAX );
                break;
              case '?':
                if(optopt == 'f'){
                    printf("Option -f requires an argument.\n");
                    break;
                }
                else if (isprint(optopt)){
                    printf("Unknown option '-%d'.\n", optopt);
                    break;
                }
                else{
                    printf("Unknown option character '\\x%x'.\n", optopt);
                    break;
                }
              default:
                abort();
                break;
            }
        }
    }

	/*********************
	 * Returns the count of packets
	 * @param handle - handle to the pcap file
	 * @return
	 */
    int countPackets(pcap_t* handle){
    	//Pcap Header Pointer
        struct pcap_pkthdr *header;
        //Pcap Data Pointer
        u_char *pkt_data;
        //Counter
        int count = 0;

        //Looping through Pcap file
        while(pcap_next_ex(handle, &header, &pkt_data) == 1)
        	count++;
        //Rewinding Pcap File
        FILE* pcapFile = pcap_file(handle);
		rewind( pcapFile );
		fseek( pcapFile, 24, SEEK_SET );
        return count;
    }


    /**************************************************************
     * Function that runs through the pcap file and collects information
     * on each packet
     * @param handle - Handle to the pcap file
     * @param packetStream - Array of packets
     * @param arguments - Arguments to test for verbose mode
     *************************************************************/
    void setPackets(pcap_t* handle, packet* packetStream, argparse arguments){
    	//Pcap Header Pointer
        struct pcap_pkthdr *header;
        //Pcap Data Pointer
        u_char *pkt_data;
        //OSI Headers
        struct ethhdr* ethh;
        struct iphdr* iph;
        struct tcphdr* tcph;
        int count = 0;
        //Loop through all the packets
        while(pcap_next_ex(handle, &header, &pkt_data) == 1){
            //Setting Headers
            ethh = (struct ethhdr*)pkt_data;
            iph = (struct iphdr*)(pkt_data + sizeof(struct ethhdr));
            tcph = (struct tcphdr*)(pkt_data + sizeof(struct ethhdr) + (iph->ihl*4));

            //Ethernet
            //Size on Wire
            packetStream[count].etherWire = header->len;
            //Payload Size
            packetStream[count].etherSize = header->len - ETHERNET_HEADER_SIZE;

            //IP
            //Header
            packetStream[count].ipHdrSize = ((iph->ihl)*4);
            //Payload
            packetStream[count].ipSize = ((header->len - ETHERNET_HEADER_SIZE) - (iph->ihl*4));
            //Size
            packetStream[count].ipLength = ntohs(iph->tot_len);
            //Zeroing out IP Source
            memset(&packetStream[count].ipSource, 0, sizeof(packetStream[count].ipSource));
            //Setting IP Source
            packetStream[count].ipSource.sin_addr.s_addr = iph->saddr;
            //Zeroing out IP Destination
            memset(&packetStream[count].ipDestination, 0, sizeof(packetStream[count].ipDestination));
            //Setting IP Destination
            packetStream[count].ipDestination.sin_addr.s_addr = iph->daddr;

            //TCP
            //Header
            packetStream[count].tcpHdrSize = (tcph->doff)*4;
            //Payload
            packetStream[count].tcpSize = ((header->len - ETHERNET_HEADER_SIZE) - (iph->ihl*4) - (tcph->doff*4));
            //Destination Port
            packetStream[count].tcpPortDestination = ntohs(tcph->dest);
            //Source Port
            packetStream[count].tcpPortSource = ntohs(tcph->source);

            /*******************************************************
             * Print all information about packet if verbose mode is one
             ******************************************************/
            /*if(arguments.verbosemode == 1){
            	printf("\n\nPacket# [%d], with length of [%d]\n", count + 1, header->len);
				printf("Ethernet Information-\n");
				printf("\tSource Ethernet: %s\n", ether_ntoa(ethh->h_source));
				printf("\tDestination Ethernet: %s\n", ether_ntoa(ethh->h_dest));
				printf("\tSize of Ethernet Payload: %d\n", header->len - ETHERNET_HEADER_SIZE);
				printf("\tProtocol Type: %u\n", (unsigned short)ethh->h_proto);
				printf("IP Information-\n");
				printf("\tIP Version: %d\n", (unsigned int)(iph->version));
				printf("\tIP Address Source: %s\n", inet_ntoa(packetStream[count].ipSource.sin_addr));
				printf("\tIP Address Destination: %s\n", inet_ntoa(packetStream[count].ipSource.sin_addr));
				printf("\tIP Protocol: %d\n", (unsigned int)(iph->protocol));
				printf("\tIP Length: %u\n", ntohs(iph->tot_len));
				printf("\tSize of IP Header (Bytes): %d\n", (iph->ihl)*4);
				printf("\tSize of IP Payload (Bytes): %d\n", ((header->len - ETHERNET_HEADER_SIZE) - (iph->ihl*4)));
				printf("TCP Information-\n");
				printf("\tTCP Destination: %u\n", ntohs(tcph->dest));
				printf("\tTCP Source: %u\n", ntohs(tcph->source));
				printf("\tLength of TCP Header (Bytes): %d\n", (tcph->doff)*4);
				printf("\tSize of TCP Payload (Bytes): %d\n", ((header->len - ETHERNET_HEADER_SIZE) - (iph->ihl*4) - (tcph->doff*4)));
            }*/


            count++;
        }

        //Rewinding Pcap File
        FILE* pcapFile = pcap_file(handle);
		rewind( pcapFile );
		fseek( pcapFile, 24, SEEK_SET );

    }

    //Calculations Functions

    void quartileCalc(int count, int* quartile){
    	int x = count/2;
    	int y = count - x;
    	int a = x/2;
    	int b = x-a;
    	int c = y/2;
    	quartile[0] = a;
    	quartile[1] = a + b;
    	quartile[2] = quartile[1] + c;
    	quartile[3] = count;
    }

    void packetMinMaxEther(packet* packetStream, int* minMax, int start, int finish){
    	minMax[0] = packetStream[start].etherSize;
    	minMax[1] = packetStream[start].etherSize;
    	int i;
    	for(i = start; i < finish; i++){
    		if(packetStream[i].etherSize < minMax[0])
    			minMax[0] = packetStream[i].etherSize;
    		if(packetStream[i].etherSize > minMax[1])
    			minMax[1] = packetStream[i].etherSize;
    	}
    }

    void packetMinMaxIp(packet* packetStream, int* minMax, int start, int finish){
    	minMax[0] = packetStream[start].ipSize;
    	minMax[1] = packetStream[start].ipSize;
    	int i;
    	for(i = start; i < finish; i++){
    		if(packetStream[i].ipSize < minMax[0])
    			minMax[0] = packetStream[i].ipSize;
    		if(packetStream[i].ipSize > minMax[1])
    			minMax[1] = packetStream[i].ipSize;
    	}
    }

    void packetMinMaxIpHdr(packet* packetStream, int* minMax, int start, int finish){
    	minMax[0] = packetStream[start].ipHdrSize;
    	minMax[1] = packetStream[start].ipHdrSize;
    	int i;
    	for(i = start; i < finish; i++){
    		if(packetStream[i].ipHdrSize < minMax[0])
    			minMax[0] = packetStream[i].ipHdrSize;
    		if(packetStream[i].ipHdrSize > minMax[1])
    			minMax[1] = packetStream[i].ipHdrSize;
    	}
    }

    void packetMinMaxTcp(packet* packetStream, int* minMax, int start, int finish){
    	minMax[0] = packetStream[start].tcpSize;
    	minMax[1] = packetStream[start].tcpSize;
    	int i;
    	for(i = start; i < finish; i++){
    		if(packetStream[i].tcpSize < minMax[0])
    			minMax[0] = packetStream[i].tcpSize;
    		if(packetStream[i].tcpSize > minMax[1])
    			minMax[1] = packetStream[i].tcpSize;
    	}
    }

    void packetMinMaxTcpHdr(packet* packetStream, int* minMax, int start, int finish){
    	minMax[0] = packetStream[start].tcpHdrSize;
    	minMax[1] = packetStream[start].tcpHdrSize;
    	int i;
    	for(i = start; i < finish; i++){
    		if(packetStream[i].tcpHdrSize < minMax[0])
    			minMax[0] = packetStream[i].tcpHdrSize;
    		if(packetStream[i].tcpHdrSize > minMax[1])
    			minMax[1] = packetStream[i].tcpHdrSize;
    	}
    }

    /********************************
     * Calculating Ethernet Mean
     * @param packetStream - Packet Array
     * @param start - Start Boundary
     * @param finish - End Boundary
     * @return mean value
     ********************************/
    double calcEtherMean(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].etherSize;
    	}
    	mean = mean / (finish - start);
    	return mean;
    }

    double calcEtherStd(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	double std = 0;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].etherSize;
    	}
    	mean = mean / (finish - start);
    	for(i=start;i <finish; i++){
    		std += pow((packetStream[i].etherSize - mean),2);
    	}
    	if(mean == 0)
    		return 0;
    	std = std / (finish - start);
    	std = sqrt(std);
    	return std;
    }

    double calcIpMean(packet* packetStream, int start, int finish){
     	double mean = 0;
     	int i;
     	for(i = start;i < finish; i++){
     		mean += packetStream[i].ipSize;
     	}
     	mean = mean / (finish - start);
     	return mean;
     }

    double calcIpStd(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	double std = 0;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].ipSize;
    	}
    	mean = mean / (finish - start);
    	for(i=start;i <finish; i++){
    		std += pow((packetStream[i].ipSize - mean),2);
    	}
    	if(mean == 0)
    		return 0;
    	std = std / (finish - start);
    	std = sqrt(std);
    	return std;
    }

    double calcIpHdrStd(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	double std = 0;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].ipHdrSize;
    	}
    	mean = mean / (finish - start);
    	for(i=start;i <finish; i++){
    		std += pow((packetStream[i].ipHdrSize - mean),2);
    	}
    	if(mean == 0)
    		return 0;
    	std = std / (finish - start);
    	std = sqrt(std);
    	return std;
    }

    double calcIpHdrMean(packet* packetStream, int start, int finish){
     	double mean = 0;
     	int i;
     	for(i = start;i < finish; i++){
     		mean += packetStream[i].ipHdrSize;
     	}
     	mean = mean / (finish - start);
     	return mean;
     }

    double calcTcpMean(packet* packetStream, int start, int finish){
     	double mean = 0;
     	int i;
     	for(i = start;i < finish; i++){
     		mean += packetStream[i].tcpSize;
     	}
     	mean = mean / (finish - start);
     	return mean;
     }

    double calcTcpHdrMean(packet* packetStream, int start, int finish){
     	double mean = 0;
     	int i;
     	for(i = start;i < finish; i++){
     		mean += packetStream[i].tcpHdrSize;
     	}
     	mean = mean / (finish - start);
     	return mean;
     }

    double calcTcpStd(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	double std = 0;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].tcpSize;
    	}
    	mean = mean / (finish - start);
    	for(i=start;i <finish; i++){
    		std += pow((packetStream[i].tcpSize - mean),2);
    	}
    	if(mean == 0)
    		return 0;
    	std = std / (finish - start);
    	std = sqrt(std);
    	return std;
    }

    double calcTcpHdrStd(packet* packetStream, int start, int finish){
    	double mean = 0;
    	int i;
    	double std = 0;
    	for(i = start;i < finish; i++){
    		mean += packetStream[i].tcpHdrSize;
    	}
    	mean = mean / (finish - start);
    	for(i=start;i <finish; i++){
    		std += pow((packetStream[i].tcpHdrSize - mean),2);
    	}
    	if(mean == 0)
    		return 0;
    	std = std / (finish - start);
    	std = sqrt(std);
    	return std;
    }


    void discriminatorCalc(int count, int* quartile, packet* packetStream, stream* stream){
    	int temp[2] = {0,0};
    	stream->etherMean = calcEtherMean(packetStream, 0, count);
		stream->etherStd = calcEtherStd(packetStream, 0, count);
		packetMinMaxEther(packetStream, temp, 0, count);
		stream->etherMin = temp[0];
		stream->etherMax = temp[1];
		//Ethernet Size Quartile Calcs
		memset(&temp, 0, sizeof(temp));
		stream->q1EtherMean = calcEtherMean(packetStream, 0, quartile[0]);
		packetMinMaxEther(packetStream, temp, 0, quartile[0]);
		stream->q1EtherMin = temp[0];
		stream->q1EtherMax = temp[1];
		stream->q2EtherMean = calcEtherMean(packetStream, quartile[0], quartile[1]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxEther(packetStream, temp, quartile[0], quartile[1]);
		stream->q2EtherMin = temp[0];
		stream->q2EtherMax = temp[1];
		memset(&temp, 0, sizeof(temp));
		stream->q3EtherMean = calcEtherMean(packetStream, quartile[1], quartile[2]);
		packetMinMaxEther(packetStream, temp, quartile[1], quartile[2]);
		stream->q3EtherMin = temp[0];
		stream->q3EtherMax = temp[1];
		stream->q4EtherMean = calcEtherMean(packetStream, quartile[2], quartile[3]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxEther(packetStream, temp, quartile[2], quartile[3]);
		stream->q4EtherMin = temp[0];
		stream->q4EtherMax = temp[1];
		//Ethernet Standard Deviation Quartile Calcs
		stream->q1EtherStd = calcEtherStd(packetStream, 0, quartile[0]);
		stream->q2EtherStd = calcEtherStd(packetStream, quartile[0], quartile[1]);
		stream->q3EtherStd = calcEtherStd(packetStream, quartile[1], quartile[2]);
		stream->q4EtherStd = calcEtherStd(packetStream, quartile[2], quartile[3]);

		//IP Size Calc
		stream->ipMean = calcIpMean(packetStream, 0, count);
		stream->ipStd = calcIpStd(packetStream, 0, count);
		stream->ipHdrMean = calcIpHdrMean(packetStream, 0, count);
		stream->ipHdrStd = calcIpHdrStd(packetStream, 0, count);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIp(packetStream, temp, 0, count);
		stream->ipMin = temp[0];
		stream->ipMax = temp[1];
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIpHdr(packetStream, temp, 0, count);
		stream->ipHdrMin = temp[0];
		stream->ipHdrMax = temp[1];
		//IP Quartile Mean Calc
		stream->q1IpMean = calcIpMean(packetStream, 0, quartile[0]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIp(packetStream, temp, 0, quartile[0]);
		stream->q1IpMin = temp[0];
		stream->q1IpMax = temp[1];
		stream->q2IpMean = calcIpMean(packetStream, quartile[0], quartile[1]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIp(packetStream, temp, quartile[0], quartile[1]);
		stream->q2IpMin = temp[0];
		stream->q2IpMax = temp[1];
		stream->q3IpMean = calcIpMean(packetStream, quartile[1], quartile[2]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIp(packetStream, temp, quartile[1], quartile[2]);
		stream->q3IpMin = temp[0];
		stream->q3IpMax = temp[1];
		stream->q4IpMean = calcIpMean(packetStream, quartile[2], quartile[3]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIp(packetStream, temp, quartile[2], quartile[3]);
		stream->q4IpMin = temp[0];
		stream->q4IpMax = temp[1];
		//IP Quartile Header Calcs
		stream->q1IpHdrMean = calcIpHdrMean(packetStream, 0, quartile[0]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIpHdr(packetStream, temp, 0, quartile[0]);
		stream->q1IpHdrMin = temp[0];
		stream->q1IpHdrMax = temp[1];
		stream->q2IpHdrMean = calcIpHdrMean(packetStream, quartile[0], quartile[1]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIpHdr(packetStream, temp, quartile[0], quartile[1]);
		stream->q2IpHdrMin = temp[0];
		stream->q2IpHdrMax = temp[1];
		stream->q3IpHdrMean = calcIpHdrMean(packetStream, quartile[1], quartile[2]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIpHdr(packetStream, temp, quartile[1], quartile[2]);
		stream->q3IpHdrMin = temp[0];
		stream->q3IpHdrMax = temp[1];
		stream->q4IpHdrMean = calcIpHdrMean(packetStream, quartile[2], quartile[3]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxIpHdr(packetStream, temp, quartile[2], quartile[3]);
		stream->q4IpHdrMin = temp[0];
		stream->q4IpHdrMax = temp[1];
		//IP Quartile Standard Deviation Calc
		stream->q1IpStd = calcIpStd(packetStream, 0, quartile[0]);
		stream->q2IpStd = calcIpStd(packetStream, quartile[0], quartile[1]);
		stream->q3IpStd = calcIpStd(packetStream, quartile[1], quartile[2]);
		stream->q4IpStd = calcIpStd(packetStream, quartile[2], quartile[3]);
		stream->q1IpHdrStd = calcIpHdrStd(packetStream, 0, quartile[0]);
		stream->q2IpHdrStd = calcIpHdrStd(packetStream, quartile[0], quartile[1]);
		stream->q3IpHdrStd = calcIpHdrStd(packetStream, quartile[1], quartile[2]);
		stream->q4IpHdrStd = calcIpHdrStd(packetStream, quartile[2], quartile[3]);

		//TCP Stream Mean/STD Calcs
		stream->tcpMean = calcTcpMean(packetStream, 0, count);
		stream->tcpHdrMean = calcTcpHdrMean(packetStream, 0, count);
		stream->tcpStd = calcTcpStd(packetStream, 0, count);
		stream->tcpHdrStd = calcTcpHdrStd(packetStream, 0, count);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcp(packetStream, temp, 0, count);
		stream->tcpMin = temp[0];
		stream->tcpMax = temp[1];
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcpHdr(packetStream, temp, 0, count);
		stream->tcpHdrMin = temp[0];
		stream->tcpHdrMax = temp[1];
		//TCP Quartile Mean Calcs
		stream->q1TcpMean = calcTcpMean(packetStream, 0, quartile[0]);
		//stream->q1TcpHdrStd = calcTcpHdrStd(packetStream, 0, quartile[0]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcp(packetStream, temp, 0, quartile[0]);
		stream->q1TcpMin = temp[0];
		stream->q1TcpMax = temp[1];
		stream->q2TcpMean = calcTcpMean(packetStream, quartile[0], quartile[1]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcp(packetStream, temp, quartile[0], quartile[1]);
		stream->q2TcpMin = temp[0];
		stream->q2TcpMax = temp[1];
		stream->q3TcpMean = calcTcpMean(packetStream, quartile[1], quartile[2]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcp(packetStream, temp, quartile[1], quartile[2]);
		stream->q3TcpMin = temp[0];
		stream->q3TcpMax = temp[1];
		stream->q4TcpMean = calcTcpMean(packetStream, quartile[2], quartile[3]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcp(packetStream, temp, quartile[2], quartile[3]);
		stream->q4TcpMin = temp[0];
		stream->q4TcpMax = temp[1];
		//TCP Quartile Header Calcs
		stream->q1TcpHdrMean = calcTcpHdrMean(packetStream, 0, quartile[0]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcpHdr(packetStream, temp, 0, quartile[0]);
		stream->q1TcpHdrMin = temp[0];
		stream->q1TcpHdrMax = temp[1];
		stream->q2TcpHdrMean = calcTcpHdrMean(packetStream, quartile[0], quartile[1]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcpHdr(packetStream, temp, quartile[0], quartile[1]);
		stream->q2TcpHdrMin = temp[0];
		stream->q2TcpHdrMax = temp[1];
		stream->q3TcpHdrMean = calcTcpHdrMean(packetStream, quartile[1], quartile[2]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcpHdr(packetStream, temp, quartile[1], quartile[2]);
		stream->q3TcpHdrMin = temp[0];
		stream->q3TcpHdrMax = temp[1];
		stream->q4TcpHdrMean = calcTcpHdrMean(packetStream, quartile[2], quartile[3]);
		memset(&temp, 0, sizeof(temp));
		packetMinMaxTcpHdr(packetStream, temp, quartile[2], quartile[3]);
		stream->q4TcpHdrMin = temp[0];
		stream->q4TcpHdrMax = temp[1];
		//TCP Quartile STD Calcs
		stream->q1TcpStd = calcTcpStd(packetStream, 0, quartile[0]);
		stream->q2TcpStd = calcTcpStd(packetStream, quartile[0], quartile[1]);
		stream->q3TcpStd = calcTcpStd(packetStream, quartile[1], quartile[2]);
		stream->q4TcpStd = calcTcpStd(packetStream, quartile[2], quartile[3]);
		stream->q1TcpHdrStd = calcTcpHdrStd(packetStream, 0, quartile[0]);
		stream->q2TcpHdrStd = calcTcpHdrStd(packetStream, quartile[0], quartile[1]);
		stream->q3TcpHdrStd = calcTcpHdrStd(packetStream, quartile[1], quartile[2]);
		stream->q4TcpHdrStd = calcTcpHdrStd(packetStream, quartile[2], quartile[3]);
    }

    /************************************************
     * Displays output at the end of the program
     * @param count - Number of Packets in the stream
     ************************************************/
    void displayOutput(int count, int* quartile, packet* packetStream, stream stream){
    	printf("*************************\n");
    	printf("\tOutput:\n");
    	printf("*************************\n");
    	printf("Total Packet Count: \t[%i]\n", count);
    	printf("Quartile Breakdown:\n");
    	printf("Q1: %d, Q2: %d, Q3: %d, Q4: %d\n", quartile[0], quartile[1], quartile[2], quartile[3]);
    	printf("*************************\n");
    	printf("Stream Discriminators:\n");
    	printf("\tEthernet Mean: \t%.2f\n", stream.etherMean);
    	printf("\tEthernet STD: \t%.2f\n", stream.etherStd);
    	printf("\tEthernet Min: \t%i\n", stream.etherMin);
    	printf("\tEthernet Max: \t%i\n", stream.etherMax);
    	printf("\tIP Mean: \t%.2f\n", stream.ipMean);
    	printf("\tIP STD: \t%.2f\n", stream.ipStd);
    	printf("\tIP Min: \t%i\n", stream.ipMin);
    	printf("\tIP Max: \t%i\n", stream.ipMax);
    	printf("\tIP Header Mean: %.2f\n", stream.ipHdrMean);
    	printf("\tIP Header STD: \t%.2f\n", stream.ipHdrStd);
    	printf("\tIP Header Min: \t%i\n", stream.ipHdrMin);
    	printf("\tIP Header Max: \t%i\n", stream.ipHdrMax);
    	printf("\tTCP Mean: \t%.2f\n", stream.tcpMean);
    	printf("\tTCP STD: \t%.2f\n", stream.tcpStd);
    	printf("\tTCP Min: \t%i\n", stream.tcpMin);
    	printf("\tTCP Max: \t%i\n", stream.tcpMax);
    	printf("\tTCP Header Mean:%.2f\n", stream.tcpHdrMean);
    	printf("\tTCP Header STD: %.2f\n", stream.tcpHdrStd);
    	printf("\tTCP Header Min: %i\n", stream.tcpHdrMin);
    	printf("\tTCP Header Max: %i\n", stream.tcpHdrMax);
    	printf("*************************\n");
    	printf("Quartile Calculations:\n");
    	printf("Q1:\n");
    	printf("\tEthernet Mean: \t%.2f\n", stream.q1EtherMean);
    	printf("\tEthernet STD: \t%.2f\n", stream.q1EtherStd);
    	printf("\tEthernet Min: \t%i\n", stream.q1EtherMin);
    	printf("\tEthernet Max: \t%i\n", stream.q1EtherMax);
    	printf("\tIP Mean: \t%.2f\n", stream.q1IpMean);
    	printf("\tIP STD: \t%.2f\n", stream.q1IpStd);
    	printf("\tIP Min: \t%i\n", stream.q1IpMin);
    	printf("\tIP Max: \t%i\n", stream.q1IpMax);
    	printf("\tIP Header Mean: %.2f\n", stream.q1IpHdrMean);
    	printf("\tIP Header STD:  %.2f\n", stream.q1IpHdrStd);
    	printf("\tIP Min Header:  %i\n", stream.q1IpHdrMin);
    	printf("\tIP Max Header:  %i\n", stream.q1IpHdrMax);
    	printf("\tTCP Mean: \t%.2f\n", stream.q1TcpMean);
    	printf("\tTCP STD: \t%.2f\n", stream.q1TcpStd);
    	printf("\tTCP Min: \t%i\n", stream.q1TcpMin);
    	printf("\tTCP Max: \t%i\n", stream.q1TcpMax);
    	printf("\tTCP Header Mean:%.2f\n", stream.q1TcpHdrMean);
    	printf("\tTCP Header STD: %.2f\n", stream.q1TcpHdrStd);
    	printf("\tTCP Min Header: %i\n", stream.q1TcpHdrMin);
    	printf("\tTCP Max Header: %i\n", stream.q1TcpHdrMax);
    	printf("Q2:\n");
    	printf("\tEthernet Mean: \t%.2f\n", stream.q2EtherMean);
    	printf("\tEthernet STD: \t%.2f\n", stream.q2EtherStd);
    	printf("\tEthernet Min: \t%i\n", stream.q2EtherMin);
    	printf("\tEthernet Max: \t%i\n", stream.q2EtherMax);
    	printf("\tIP Mean: \t%.2f\n", stream.q2IpMean);
    	printf("\tIP STD: \t%.2f\n", stream.q2IpStd);
    	printf("\tIP Min: \t%i\n", stream.q2IpMin);
    	printf("\tIP Max: \t%i\n", stream.q2IpMax);
    	printf("\tIP Header Mean: %.2f\n", stream.q2IpHdrMean);
    	printf("\tIP Header STD:  %.2f\n", stream.q2IpHdrStd);
    	printf("\tIP Min Header:  %i\n", stream.q2IpHdrMin);
    	printf("\tIP Max Header:  %i\n", stream.q2IpHdrMax);
    	printf("\tTCP Mean: \t%.2f\n", stream.q2TcpMean);
    	printf("\tTCP STD: \t%.2f\n", stream.q2TcpStd);
    	printf("\tTCP Min: \t%i\n", stream.q2TcpMin);
    	printf("\tTCP Max: \t%i\n", stream.q2TcpMax);
    	printf("\tTCP Header Mean:%.2f\n", stream.q2TcpHdrMean);
    	printf("\tTCP Header STD: %.2f\n", stream.q2TcpHdrStd);
    	printf("\tTCP Min Header: %i\n", stream.q2TcpHdrMin);
    	printf("\tTCP Max Header: %i\n", stream.q2TcpHdrMax);
		printf("Q3:\n");
    	printf("\tEthernet Mean: \t%.2f\n", stream.q3EtherMean);
    	printf("\tEthernet STD: \t%.2f\n", stream.q3EtherStd);
    	printf("\tEthernet Min: \t%i\n", stream.q3EtherMin);
    	printf("\tEthernet Max: \t%i\n", stream.q3EtherMax);
    	printf("\tIP Mean: \t%.2f\n", stream.q3IpMean);
    	printf("\tIP STD: \t%.2f\n", stream.q3IpStd);
    	printf("\tIP Min: \t%i\n", stream.q3IpMin);
    	printf("\tIP Max: \t%i\n", stream.q3IpMax);
    	printf("\tIP Header Mean: %.2f\n", stream.q3IpHdrMean);
    	printf("\tIP Header STD:  %.2f\n", stream.q3IpHdrStd);
    	printf("\tIP Min Header:  %i\n", stream.q3IpHdrMin);
    	printf("\tIP Max Header:  %i\n", stream.q3IpHdrMax);
    	printf("\tTCP Mean: \t%.2f\n", stream.q3TcpMean);
    	printf("\tTCP STD: \t%.2f\n", stream.q3TcpStd);
    	printf("\tTCP Min: \t%i\n", stream.q3TcpMin);
    	printf("\tTCP Max: \t%i\n", stream.q3TcpMax);
    	printf("\tTCP Header Mean:%.2f\n", stream.q3TcpHdrMean);
    	printf("\tTCP Header STD: %.2f\n", stream.q3TcpHdrStd);
    	printf("\tTCP Min Header: %i\n", stream.q3TcpHdrMin);
    	printf("\tTCP Max Header: %i\n", stream.q3TcpHdrMax);
    	printf("Q4:\n");
    	printf("\tEthernet Mean: \t%.2f\n", stream.q4EtherMean);
    	printf("\tEthernet STD: \t%.2f\n", stream.q4EtherStd);
    	printf("\tEthernet Min: \t%i\n", stream.q4EtherMin);
    	printf("\tEthernet Max: \t%i\n", stream.q4EtherMax);
    	printf("\tIP Mean: \t%.2f\n", stream.q4IpMean);
    	printf("\tIP STD: \t%.2f\n", stream.q4IpStd);
    	printf("\tIP Min: \t%i\n", stream.q4IpMin);
    	printf("\tIP Max: \t%i\n", stream.q4IpMax);
    	printf("\tIP Header Mean: %.2f\n", stream.q4IpHdrMean);
    	printf("\tIP Header STD:  %.2f\n", stream.q4IpHdrStd);
    	printf("\tIP Min Header:  %i\n", stream.q4IpHdrMin);
    	printf("\tIP Max Header:  %i\n", stream.q4IpHdrMax);
    	printf("\tTCP Mean: \t%.2f\n", stream.q4TcpMean);
    	printf("\tTCP STD: \t%.2f\n", stream.q4TcpStd);
    	printf("\tTCP Min: \t%i\n", stream.q4TcpMin);
    	printf("\tTCP Max: \t%i\n", stream.q4TcpMax);
    	printf("\tTCP Header Mean:%.2f\n", stream.q4TcpHdrMean);
    	printf("\tTCP Header STD: %.2f\n", stream.q4TcpHdrStd);
    	printf("\tTCP Min Header: %i\n", stream.q4TcpHdrMin);
    	printf("\tTCP Max Header: %i\n", stream.q4TcpHdrMax);
    	printf("\n\n\n");
    }

    void verbosePacketOutput(int count, packet* packetStream){
    	printf("\n\n*****VERBOSE OUTPUT******\n\n");
    	int i;
    	for(i = 0; i<(count); i++){
			printf("\n\nPacket# [%d], with length of [%d]\n", i + 1, packetStream[i].etherWire);
			printf("Ethernet Information-\n");
			printf("\tSize of Ethernet Payload: %d\n", packetStream[i].etherSize);
			printf("IP Information-\n");
			printf("\tIP Address Source: %s\n", inet_ntoa(packetStream[i].ipSource.sin_addr));
			printf("\tIP Address Destination: %s\n", inet_ntoa(packetStream[i].ipSource.sin_addr));
			printf("\tIP Length: %u\n", packetStream[i].ipLength);
			printf("\tSize of IP Header (Bytes): %d\n", packetStream[i].ipHdrSize);
			printf("\tSize of IP Payload (Bytes): %d\n", packetStream[i].ipSize);
			printf("TCP Information-\n");
			printf("\tTCP Destination: %u\n", packetStream[i].tcpPortDestination);
			printf("\tTCP Source: %u\n", packetStream[i].tcpPortSource);
			printf("\tLength of TCP Header (Bytes): %d\n", packetStream[i].tcpHdrSize);
			printf("\tSize of TCP Payload (Bytes): %d\n", packetStream[i].tcpSize);
    	}
    }

    /**********************
     * Sorting Functions
     **********************/

    void sortPacketsEther(int count, packet* packetStream){
    	int i;
    	for(i=0;i<(count);i++){
    		int j;
    		for(j=0;j<((count-i)-1);j++){
    			if(packetStream[j].etherSize > packetStream[j+1].etherSize){
    				packet temp=packetStream[j];
    				packetStream[j] = packetStream[j+1];
    				packetStream[j+1] = temp;
    			}
    		}
    	}
    }

    void sortPacketsIp(int count, packet* packetStream){
    	int i;
    	for(i=0;i<(count);i++){
    		int j;
    		for(j=0;j<((count-i)-1);j++){
    			if(packetStream[j].ipSize > packetStream[j+1].ipSize){
    				packet temp=packetStream[j];
    				packetStream[j] = packetStream[j+1];
    				packetStream[j+1] = temp;
    			}
    		}
    	}
    }

    void sortPacketsIpHdr(int count, packet* packetStream){
    	int i;
    	for(i=0;i<(count);i++){
    		int j;
    		for(j=0;j<((count-i)-1);j++){
    			if(packetStream[j].ipHdrSize > packetStream[j+1].ipHdrSize){
    				packet temp=packetStream[j];
    				packetStream[j] = packetStream[j+1];
    				packetStream[j+1] = temp;
    			}
    		}
    	}
    }

    void sortPacketsTcp(int count, packet* packetStream){
    	int i;
    	for(i=0;i<(count);i++){
    		int j;
    		for(j=0;j<((count-i)-1);j++){
    			if(packetStream[j].tcpSize > packetStream[j+1].tcpSize){
    				packet temp=packetStream[j];
    				packetStream[j] = packetStream[j+1];
    				packetStream[j+1] = temp;
    			}
    		}
    	}
    }

    void sortPacketsTcpHdr(int count, packet* packetStream){
    	int i;
    	for(i=0;i<(count);i++){
    		int j;
    		for(j=0;j<((count-i)-1);j++){
    			if(packetStream[j].tcpHdrSize > packetStream[j+1].tcpHdrSize){
    				packet temp=packetStream[j];
    				packetStream[j] = packetStream[j+1];
    				packetStream[j+1] = temp;
    			}
    		}
    	}
    }


    /*******************
     * Mysql functions
     *******************/

    MYSQL* mysqlConnector(MYSQL *mysql){

    	mysql = mysql_init(NULL);
    	if (!mysql_real_connect(mysql,"localhost","pcap","P@ssw0rd","pcap",0,NULL,0))
    	{
    	    fprintf(stderr, "Failed to connect to database: Error: %s\n",
    	          mysql_error(mysql));
    	}
    	return mysql;
    }

my_ulonglong saveStreamInfo( MYSQL *mysql, char *md5, stream* mainStream, stream *etherStream, stream *ipStream, stream *ipHdrStream, stream *tcpStream, stream *tcpHdrStream )
{
	char sql[3000];
	char etherSql[3000];
	char ipSql[3000];
	char ipHdrSql[3000];
	char tcpSql[3000];
	char tcpHdrSql[3000];
	int isSsh = 1;
	unsigned int etherId = 0;
	unsigned int ipId = 0;
	unsigned int ipHdrId = 0;
	unsigned int tcpId = 0;
	unsigned int tcpHdrId = 0;

	//insert stream sorted by ethernet
	sprintf(etherSql, "INSERT INTO stream VALUES(NULL, '%s', 1, NULL, NULL, NULL, NULL, NULL,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	etherStream->etherMean,
	etherStream->q1EtherMean,
	etherStream->q2EtherMean,
	etherStream->q3EtherMean,
	etherStream->q4EtherMean,
	etherStream->etherStd,
	etherStream->q1EtherStd,
	etherStream->q2EtherStd,
	etherStream->q3EtherStd,
	etherStream->q4EtherStd,
	etherStream->etherMin,
	etherStream->q1EtherMin,
	etherStream->q2EtherMin,
	etherStream->q3EtherMin,
	etherStream->q4EtherMin,
	etherStream->etherMax,
	etherStream->q1EtherMax,
	etherStream->q2EtherMax,
	etherStream->q3EtherMax,
	etherStream->q4EtherMax,
	etherStream->ipMean,
	etherStream->q1IpMean,
	etherStream->q2IpMean,
	etherStream->q3IpMean,
	etherStream->q4IpMean,
	etherStream->ipHdrMean,
	etherStream->q1IpHdrMean,
	etherStream->q2IpHdrMean,
	etherStream->q3IpHdrMean,
	etherStream->q4IpHdrMean,
	etherStream->ipStd,
	etherStream->q1IpStd,
	etherStream->q2IpStd,
	etherStream->q3IpStd,
	etherStream->q4IpStd,
	etherStream->ipHdrStd,
	etherStream->q1IpHdrStd,
	etherStream->q2IpHdrStd,
	etherStream->q3IpHdrStd,
	etherStream->q4IpHdrStd,
	etherStream->ipMin,
	etherStream->q1IpMin,
	etherStream->q2IpMin,
	etherStream->q3IpMin,
	etherStream->q4IpMin,
	etherStream->ipHdrMin,
	etherStream->q1IpHdrMin,
	etherStream->q2IpHdrMin,
	etherStream->q3IpHdrMin,
	etherStream->q4IpHdrMin,
	etherStream->ipMax,
	etherStream->q1IpMax,
	etherStream->q2IpMax,
	etherStream->q3IpMax,
	etherStream->q4IpMax,
	etherStream->ipHdrMax,
	etherStream->q1IpHdrMax,
	etherStream->q2IpHdrMax,
	etherStream->q3IpHdrMax,
	etherStream->q4IpHdrMax,
	etherStream->tcpMean,
	etherStream->q1TcpMean,
	etherStream->q2TcpMean,
	etherStream->q3TcpMean,
	etherStream->q4TcpMean,
	etherStream->tcpHdrMean,
	etherStream->q1TcpHdrMean,
	etherStream->q2TcpHdrMean,
	etherStream->q3TcpHdrMean,
	etherStream->q4TcpHdrMean,
	etherStream->tcpStd,
	etherStream->q1TcpStd,
	etherStream->q2TcpStd,
	etherStream->q3TcpStd,
	etherStream->q4TcpStd,
	etherStream->tcpHdrStd,
	etherStream->q1TcpHdrStd,
	etherStream->q2TcpHdrStd,
	etherStream->q3TcpHdrStd,
	etherStream->q4TcpHdrStd,
	etherStream->tcpMin,
	etherStream->q1TcpMin,
	etherStream->q2TcpMin,
	etherStream->q3TcpMin,
	etherStream->q4TcpMin,
	etherStream->tcpHdrMin,
	etherStream->q1TcpHdrMin,
	etherStream->q2TcpHdrMin,
	etherStream->q3TcpHdrMin,
	etherStream->q4TcpHdrMin,
	etherStream->tcpMax,
	etherStream->q1TcpMax,
	etherStream->q2TcpMax,
	etherStream->q3TcpMax,
	etherStream->q4TcpMax,
	etherStream->tcpHdrMax,
	etherStream->q1TcpHdrMax,
	etherStream->q2TcpHdrMax,
	etherStream->q3TcpHdrMax,
	etherStream->q4TcpHdrMax );
	if(mysql_query(mysql, etherSql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	etherId = mysql_insert_id( mysql );
	//printf( "Ethernet id: %u\n", etherId );
	//printf("%s\n", etherSql);

	//insert stream sorted by ip
	sprintf(ipSql, "INSERT INTO stream VALUES(NULL, '%s', 1, NULL, NULL, NULL, NULL, NULL,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	ipStream->etherMean,
	ipStream->q1EtherMean,
	ipStream->q2EtherMean,
	ipStream->q3EtherMean,
	ipStream->q4EtherMean,
	ipStream->etherStd,
	ipStream->q1EtherStd,
	ipStream->q2EtherStd,
	ipStream->q3EtherStd,
	ipStream->q4EtherStd,
	ipStream->etherMin,
	ipStream->q1EtherMin,
	ipStream->q2EtherMin,
	ipStream->q3EtherMin,
	ipStream->q4EtherMin,
	ipStream->etherMax,
	ipStream->q1EtherMax,
	ipStream->q2EtherMax,
	ipStream->q3EtherMax,
	ipStream->q4EtherMax,
	ipStream->ipMean,
	ipStream->q1IpMean,
	ipStream->q2IpMean,
	ipStream->q3IpMean,
	ipStream->q4IpMean,
	ipStream->ipHdrMean,
	ipStream->q1IpHdrMean,
	ipStream->q2IpHdrMean,
	ipStream->q3IpHdrMean,
	ipStream->q4IpHdrMean,
	ipStream->ipStd,
	ipStream->q1IpStd,
	ipStream->q2IpStd,
	ipStream->q3IpStd,
	ipStream->q4IpStd,
	ipStream->ipHdrStd,
	ipStream->q1IpHdrStd,
	ipStream->q2IpHdrStd,
	ipStream->q3IpHdrStd,
	ipStream->q4IpHdrStd,
	ipStream->ipMin,
	ipStream->q1IpMin,
	ipStream->q2IpMin,
	ipStream->q3IpMin,
	ipStream->q4IpMin,
	ipStream->ipHdrMin,
	ipStream->q1IpHdrMin,
	ipStream->q2IpHdrMin,
	ipStream->q3IpHdrMin,
	ipStream->q4IpHdrMin,
	ipStream->ipMax,
	ipStream->q1IpMax,
	ipStream->q2IpMax,
	ipStream->q3IpMax,
	ipStream->q4IpMax,
	ipStream->ipHdrMax,
	ipStream->q1IpHdrMax,
	ipStream->q2IpHdrMax,
	ipStream->q3IpHdrMax,
	ipStream->q4IpHdrMax,
	ipStream->tcpMean,
	ipStream->q1TcpMean,
	ipStream->q2TcpMean,
	ipStream->q3TcpMean,
	ipStream->q4TcpMean,
	ipStream->tcpHdrMean,
	ipStream->q1TcpHdrMean,
	ipStream->q2TcpHdrMean,
	ipStream->q3TcpHdrMean,
	ipStream->q4TcpHdrMean,
	ipStream->tcpStd,
	ipStream->q1TcpStd,
	ipStream->q2TcpStd,
	ipStream->q3TcpStd,
	ipStream->q4TcpStd,
	ipStream->tcpHdrStd,
	ipStream->q1TcpHdrStd,
	ipStream->q2TcpHdrStd,
	ipStream->q3TcpHdrStd,
	ipStream->q4TcpHdrStd,
	ipStream->tcpMin,
	ipStream->q1TcpMin,
	ipStream->q2TcpMin,
	ipStream->q3TcpMin,
	ipStream->q4TcpMin,
	ipStream->tcpHdrMin,
	ipStream->q1TcpHdrMin,
	ipStream->q2TcpHdrMin,
	ipStream->q3TcpHdrMin,
	ipStream->q4TcpHdrMin,
	ipStream->tcpMax,
	ipStream->q1TcpMax,
	ipStream->q2TcpMax,
	ipStream->q3TcpMax,
	ipStream->q4TcpMax,
	ipStream->tcpHdrMax,
	ipStream->q1TcpHdrMax,
	ipStream->q2TcpHdrMax,
	ipStream->q3TcpHdrMax,
	ipStream->q4TcpHdrMax );
	if(mysql_query(mysql, ipSql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	ipId = mysql_insert_id( mysql );
	//printf( "IP id: %u\n", ipId );
	//printf("%s\n", ipSql);

	
	//insert stream sorted by ipHdr
	sprintf(ipHdrSql, "INSERT INTO stream VALUES(NULL, '%s', 1, NULL, NULL, NULL, NULL, NULL,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	ipHdrStream->etherMean,
	ipHdrStream->q1EtherMean,
	ipHdrStream->q2EtherMean,
	ipHdrStream->q3EtherMean,
	ipHdrStream->q4EtherMean,
	ipHdrStream->etherStd,
	ipHdrStream->q1EtherStd,
	ipHdrStream->q2EtherStd,
	ipHdrStream->q3EtherStd,
	ipHdrStream->q4EtherStd,
	ipHdrStream->etherMin,
	ipHdrStream->q1EtherMin,
	ipHdrStream->q2EtherMin,
	ipHdrStream->q3EtherMin,
	ipHdrStream->q4EtherMin,
	ipHdrStream->etherMax,
	ipHdrStream->q1EtherMax,
	ipHdrStream->q2EtherMax,
	ipHdrStream->q3EtherMax,
	ipHdrStream->q4EtherMax,
	ipHdrStream->ipMean,
	ipHdrStream->q1IpMean,
	ipHdrStream->q2IpMean,
	ipHdrStream->q3IpMean,
	ipHdrStream->q4IpMean,
	ipHdrStream->ipHdrMean,
	ipHdrStream->q1IpHdrMean,
	ipHdrStream->q2IpHdrMean,
	ipHdrStream->q3IpHdrMean,
	ipHdrStream->q4IpHdrMean,
	ipHdrStream->ipStd,
	ipHdrStream->q1IpStd,
	ipHdrStream->q2IpStd,
	ipHdrStream->q3IpStd,
	ipHdrStream->q4IpStd,
	ipHdrStream->ipHdrStd,
	ipHdrStream->q1IpHdrStd,
	ipHdrStream->q2IpHdrStd,
	ipHdrStream->q3IpHdrStd,
	ipHdrStream->q4IpHdrStd,
	ipHdrStream->ipMin,
	ipHdrStream->q1IpMin,
	ipHdrStream->q2IpMin,
	ipHdrStream->q3IpMin,
	ipHdrStream->q4IpMin,
	ipHdrStream->ipHdrMin,
	ipHdrStream->q1IpHdrMin,
	ipHdrStream->q2IpHdrMin,
	ipHdrStream->q3IpHdrMin,
	ipHdrStream->q4IpHdrMin,
	ipHdrStream->ipMax,
	ipHdrStream->q1IpMax,
	ipHdrStream->q2IpMax,
	ipHdrStream->q3IpMax,
	ipHdrStream->q4IpMax,
	ipHdrStream->ipHdrMax,
	ipHdrStream->q1IpHdrMax,
	ipHdrStream->q2IpHdrMax,
	ipHdrStream->q3IpHdrMax,
	ipHdrStream->q4IpHdrMax,
	ipHdrStream->tcpMean,
	ipHdrStream->q1TcpMean,
	ipHdrStream->q2TcpMean,
	ipHdrStream->q3TcpMean,
	ipHdrStream->q4TcpMean,
	ipHdrStream->tcpHdrMean,
	ipHdrStream->q1TcpHdrMean,
	ipHdrStream->q2TcpHdrMean,
	ipHdrStream->q3TcpHdrMean,
	ipHdrStream->q4TcpHdrMean,
	ipHdrStream->tcpStd,
	ipHdrStream->q1TcpStd,
	ipHdrStream->q2TcpStd,
	ipHdrStream->q3TcpStd,
	ipHdrStream->q4TcpStd,
	ipHdrStream->tcpHdrStd,
	ipHdrStream->q1TcpHdrStd,
	ipHdrStream->q2TcpHdrStd,
	ipHdrStream->q3TcpHdrStd,
	ipHdrStream->q4TcpHdrStd,
	ipHdrStream->tcpMin,
	ipHdrStream->q1TcpMin,
	ipHdrStream->q2TcpMin,
	ipHdrStream->q3TcpMin,
	ipHdrStream->q4TcpMin,
	ipHdrStream->tcpHdrMin,
	ipHdrStream->q1TcpHdrMin,
	ipHdrStream->q2TcpHdrMin,
	ipHdrStream->q3TcpHdrMin,
	ipHdrStream->q4TcpHdrMin,
	ipHdrStream->tcpMax,
	ipHdrStream->q1TcpMax,
	ipHdrStream->q2TcpMax,
	ipHdrStream->q3TcpMax,
	ipHdrStream->q4TcpMax,
	ipHdrStream->tcpHdrMax,
	ipHdrStream->q1TcpHdrMax,
	ipHdrStream->q2TcpHdrMax,
	ipHdrStream->q3TcpHdrMax,
	ipHdrStream->q4TcpHdrMax );
	if(mysql_query(mysql, ipHdrSql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	ipHdrId = mysql_insert_id( mysql );
	//printf( "IP Hdr id: %u\n", ipHdrId );
	//printf("%s\n", ipHdrSql);

	//insert stream sorted by tcp
	sprintf(tcpSql, "INSERT INTO stream VALUES(NULL, '%s', 1, NULL, NULL, NULL, NULL, NULL,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	tcpStream->etherMean,
	tcpStream->q1EtherMean,
	tcpStream->q2EtherMean,
	tcpStream->q3EtherMean,
	tcpStream->q4EtherMean,
	tcpStream->etherStd,
	tcpStream->q1EtherStd,
	tcpStream->q2EtherStd,
	tcpStream->q3EtherStd,
	tcpStream->q4EtherStd,
	tcpStream->etherMin,
	tcpStream->q1EtherMin,
	tcpStream->q2EtherMin,
	tcpStream->q3EtherMin,
	tcpStream->q4EtherMin,
	tcpStream->etherMax,
	tcpStream->q1EtherMax,
	tcpStream->q2EtherMax,
	tcpStream->q3EtherMax,
	tcpStream->q4EtherMax,
	tcpStream->ipMean,
	tcpStream->q1IpMean,
	tcpStream->q2IpMean,
	tcpStream->q3IpMean,
	tcpStream->q4IpMean,
	tcpStream->ipHdrMean,
	tcpStream->q1IpHdrMean,
	tcpStream->q2IpHdrMean,
	tcpStream->q3IpHdrMean,
	tcpStream->q4IpHdrMean,
	tcpStream->ipStd,
	tcpStream->q1IpStd,
	tcpStream->q2IpStd,
	tcpStream->q3IpStd,
	tcpStream->q4IpStd,
	tcpStream->ipHdrStd,
	tcpStream->q1IpHdrStd,
	tcpStream->q2IpHdrStd,
	tcpStream->q3IpHdrStd,
	tcpStream->q4IpHdrStd,
	tcpStream->ipMin,
	tcpStream->q1IpMin,
	tcpStream->q2IpMin,
	tcpStream->q3IpMin,
	tcpStream->q4IpMin,
	tcpStream->ipHdrMin,
	tcpStream->q1IpHdrMin,
	tcpStream->q2IpHdrMin,
	tcpStream->q3IpHdrMin,
	tcpStream->q4IpHdrMin,
	tcpStream->ipMax,
	tcpStream->q1IpMax,
	tcpStream->q2IpMax,
	tcpStream->q3IpMax,
	tcpStream->q4IpMax,
	tcpStream->ipHdrMax,
	tcpStream->q1IpHdrMax,
	tcpStream->q2IpHdrMax,
	tcpStream->q3IpHdrMax,
	tcpStream->q4IpHdrMax,
	tcpStream->tcpMean,
	tcpStream->q1TcpMean,
	tcpStream->q2TcpMean,
	tcpStream->q3TcpMean,
	tcpStream->q4TcpMean,
	tcpStream->tcpHdrMean,
	tcpStream->q1TcpHdrMean,
	tcpStream->q2TcpHdrMean,
	tcpStream->q3TcpHdrMean,
	tcpStream->q4TcpHdrMean,
	tcpStream->tcpStd,
	tcpStream->q1TcpStd,
	tcpStream->q2TcpStd,
	tcpStream->q3TcpStd,
	tcpStream->q4TcpStd,
	tcpStream->tcpHdrStd,
	tcpStream->q1TcpHdrStd,
	tcpStream->q2TcpHdrStd,
	tcpStream->q3TcpHdrStd,
	tcpStream->q4TcpHdrStd,
	tcpStream->tcpMin,
	tcpStream->q1TcpMin,
	tcpStream->q2TcpMin,
	tcpStream->q3TcpMin,
	tcpStream->q4TcpMin,
	tcpStream->tcpHdrMin,
	tcpStream->q1TcpHdrMin,
	tcpStream->q2TcpHdrMin,
	tcpStream->q3TcpHdrMin,
	tcpStream->q4TcpHdrMin,
	tcpStream->tcpMax,
	tcpStream->q1TcpMax,
	tcpStream->q2TcpMax,
	tcpStream->q3TcpMax,
	tcpStream->q4TcpMax,
	tcpStream->tcpHdrMax,
	tcpStream->q1TcpHdrMax,
	tcpStream->q2TcpHdrMax,
	tcpStream->q3TcpHdrMax,
	tcpStream->q4TcpHdrMax );
	if(mysql_query(mysql, tcpSql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	tcpId = mysql_insert_id( mysql );
	//printf( "TCP id: %u\n", tcpId );
	//printf("%s\n", tcpSql);
	
	//insert stream sorted by tcpHdr
	sprintf(tcpHdrSql, "INSERT INTO stream VALUES(NULL, '%s', 1, NULL, NULL, NULL, NULL, NULL,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	tcpHdrStream->etherMean,
	tcpHdrStream->q1EtherMean,
	tcpHdrStream->q2EtherMean,
	tcpHdrStream->q3EtherMean,
	tcpHdrStream->q4EtherMean,
	tcpHdrStream->etherStd,
	tcpHdrStream->q1EtherStd,
	tcpHdrStream->q2EtherStd,
	tcpHdrStream->q3EtherStd,
	tcpHdrStream->q4EtherStd,
	tcpHdrStream->etherMin,
	tcpHdrStream->q1EtherMin,
	tcpHdrStream->q2EtherMin,
	tcpHdrStream->q3EtherMin,
	tcpHdrStream->q4EtherMin,
	tcpHdrStream->etherMax,
	tcpHdrStream->q1EtherMax,
	tcpHdrStream->q2EtherMax,
	tcpHdrStream->q3EtherMax,
	tcpHdrStream->q4EtherMax,
	tcpHdrStream->ipMean,
	tcpHdrStream->q1IpMean,
	tcpHdrStream->q2IpMean,
	tcpHdrStream->q3IpMean,
	tcpHdrStream->q4IpMean,
	tcpHdrStream->ipHdrMean,
	tcpHdrStream->q1IpHdrMean,
	tcpHdrStream->q2IpHdrMean,
	tcpHdrStream->q3IpHdrMean,
	tcpHdrStream->q4IpHdrMean,
	tcpHdrStream->ipStd,
	tcpHdrStream->q1IpStd,
	tcpHdrStream->q2IpStd,
	tcpHdrStream->q3IpStd,
	tcpHdrStream->q4IpStd,
	tcpHdrStream->ipHdrStd,
	tcpHdrStream->q1IpHdrStd,
	tcpHdrStream->q2IpHdrStd,
	tcpHdrStream->q3IpHdrStd,
	tcpHdrStream->q4IpHdrStd,
	tcpHdrStream->ipMin,
	tcpHdrStream->q1IpMin,
	tcpHdrStream->q2IpMin,
	tcpHdrStream->q3IpMin,
	tcpHdrStream->q4IpMin,
	tcpHdrStream->ipHdrMin,
	tcpHdrStream->q1IpHdrMin,
	tcpHdrStream->q2IpHdrMin,
	tcpHdrStream->q3IpHdrMin,
	tcpHdrStream->q4IpHdrMin,
	tcpHdrStream->ipMax,
	tcpHdrStream->q1IpMax,
	tcpHdrStream->q2IpMax,
	tcpHdrStream->q3IpMax,
	tcpHdrStream->q4IpMax,
	tcpHdrStream->ipHdrMax,
	tcpHdrStream->q1IpHdrMax,
	tcpHdrStream->q2IpHdrMax,
	tcpHdrStream->q3IpHdrMax,
	tcpHdrStream->q4IpHdrMax,
	tcpHdrStream->tcpMean,
	tcpHdrStream->q1TcpMean,
	tcpHdrStream->q2TcpMean,
	tcpHdrStream->q3TcpMean,
	tcpHdrStream->q4TcpMean,
	tcpHdrStream->tcpHdrMean,
	tcpHdrStream->q1TcpHdrMean,
	tcpHdrStream->q2TcpHdrMean,
	tcpHdrStream->q3TcpHdrMean,
	tcpHdrStream->q4TcpHdrMean,
	tcpHdrStream->tcpStd,
	tcpHdrStream->q1TcpStd,
	tcpHdrStream->q2TcpStd,
	tcpHdrStream->q3TcpStd,
	tcpHdrStream->q4TcpStd,
	tcpHdrStream->tcpHdrStd,
	tcpHdrStream->q1TcpHdrStd,
	tcpHdrStream->q2TcpHdrStd,
	tcpHdrStream->q3TcpHdrStd,
	tcpHdrStream->q4TcpHdrStd,
	tcpHdrStream->tcpMin,
	tcpHdrStream->q1TcpMin,
	tcpHdrStream->q2TcpMin,
	tcpHdrStream->q3TcpMin,
	tcpHdrStream->q4TcpMin,
	tcpHdrStream->tcpHdrMin,
	tcpHdrStream->q1TcpHdrMin,
	tcpHdrStream->q2TcpHdrMin,
	tcpHdrStream->q3TcpHdrMin,
	tcpHdrStream->q4TcpHdrMin,
	tcpHdrStream->tcpMax,
	tcpHdrStream->q1TcpMax,
	tcpHdrStream->q2TcpMax,
	tcpHdrStream->q3TcpMax,
	tcpHdrStream->q4TcpMax,
	tcpHdrStream->tcpHdrMax,
	tcpHdrStream->q1TcpHdrMax,
	tcpHdrStream->q2TcpHdrMax,
	tcpHdrStream->q3TcpHdrMax,
	tcpHdrStream->q4TcpHdrMax );
	if(mysql_query(mysql, tcpHdrSql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	tcpHdrId = mysql_insert_id( mysql );
	//printf( "TCP Hdr id: %u\n", tcpHdrId );
	//printf("%s\n", tcpHdrSql);

	//create insert string
	sprintf(sql, "INSERT INTO stream VALUES(NULL, '%s', 1, %u, %u, %u, %u, %u,"
	//Ethernet Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//IP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,"
	//TCP Values
	"%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
	"%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i,%i)",
	md5,
	etherId,
	ipId,
	ipHdrId,
	tcpId,
	tcpHdrId,
	mainStream->etherMean,
	mainStream->q1EtherMean,
	mainStream->q2EtherMean,
	mainStream->q3EtherMean,
	mainStream->q4EtherMean,
	mainStream->etherStd,
	mainStream->q1EtherStd,
	mainStream->q2EtherStd,
	mainStream->q3EtherStd,
	mainStream->q4EtherStd,
	mainStream->etherMin,
	mainStream->q1EtherMin,
	mainStream->q2EtherMin,
	mainStream->q3EtherMin,
	mainStream->q4EtherMin,
	mainStream->etherMax,
	mainStream->q1EtherMax,
	mainStream->q2EtherMax,
	mainStream->q3EtherMax,
	mainStream->q4EtherMax,
	mainStream->ipMean,
	mainStream->q1IpMean,
	mainStream->q2IpMean,
	mainStream->q3IpMean,
	mainStream->q4IpMean,
	mainStream->ipHdrMean,
	mainStream->q1IpHdrMean,
	mainStream->q2IpHdrMean,
	mainStream->q3IpHdrMean,
	mainStream->q4IpHdrMean,
	mainStream->ipStd,
	mainStream->q1IpStd,
	mainStream->q2IpStd,
	mainStream->q3IpStd,
	mainStream->q4IpStd,
	mainStream->ipHdrStd,
	mainStream->q1IpHdrStd,
	mainStream->q2IpHdrStd,
	mainStream->q3IpHdrStd,
	mainStream->q4IpHdrStd,
	mainStream->ipMin,
	mainStream->q1IpMin,
	mainStream->q2IpMin,
	mainStream->q3IpMin,
	mainStream->q4IpMin,
	mainStream->ipHdrMin,
	mainStream->q1IpHdrMin,
	mainStream->q2IpHdrMin,
	mainStream->q3IpHdrMin,
	mainStream->q4IpHdrMin,
	mainStream->ipMax,
	mainStream->q1IpMax,
	mainStream->q2IpMax,
	mainStream->q3IpMax,
	mainStream->q4IpMax,
	mainStream->ipHdrMax,
	mainStream->q1IpHdrMax,
	mainStream->q2IpHdrMax,
	mainStream->q3IpHdrMax,
	mainStream->q4IpHdrMax,
	mainStream->tcpMean,
	mainStream->q1TcpMean,
	mainStream->q2TcpMean,
	mainStream->q3TcpMean,
	mainStream->q4TcpMean,
	mainStream->tcpHdrMean,
	mainStream->q1TcpHdrMean,
	mainStream->q2TcpHdrMean,
	mainStream->q3TcpHdrMean,
	mainStream->q4TcpHdrMean,
	mainStream->tcpStd,
	mainStream->q1TcpStd,
	mainStream->q2TcpStd,
	mainStream->q3TcpStd,
	mainStream->q4TcpStd,
	mainStream->tcpHdrStd,
	mainStream->q1TcpHdrStd,
	mainStream->q2TcpHdrStd,
	mainStream->q3TcpHdrStd,
	mainStream->q4TcpHdrStd,
	mainStream->tcpMin,
	mainStream->q1TcpMin,
	mainStream->q2TcpMin,
	mainStream->q3TcpMin,
	mainStream->q4TcpMin,
	mainStream->tcpHdrMin,
	mainStream->q1TcpHdrMin,
	mainStream->q2TcpHdrMin,
	mainStream->q3TcpHdrMin,
	mainStream->q4TcpHdrMin,
	mainStream->tcpMax,
	mainStream->q1TcpMax,
	mainStream->q2TcpMax,
	mainStream->q3TcpMax,
	mainStream->q4TcpMax,
	mainStream->tcpHdrMax,
	mainStream->q1TcpHdrMax,
	mainStream->q2TcpHdrMax,
	mainStream->q3TcpHdrMax,
	mainStream->q4TcpHdrMax );
	if(mysql_query(mysql, sql)){
		printf("Error %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
	}
	//printf("%s\n", sql);

	return mysql_insert_id( mysql );
}

    void calcMd5Sum(FILE* file_name, char* md5sum){
    	int n;
    	MD5_CTX c;
        ssize_t bytes;
        unsigned char out[MD5_DIGEST_LENGTH];

        MD5_Init(&c);
        //bytes=read(file_name, buf, 512);
        fseek (file_name, 0, SEEK_END);
        long lSize = ftell(file_name);
        rewind (file_name);
        char buf[lSize];
        bytes = fread((void *)buf, 1, lSize, file_name);
        while(bytes > 0)
        {
                MD5_Update(&c, buf, bytes);
                //bytes=read(file_name, buf, 512);
                bytes = fread((void *)buf, 1, lSize, file_name);
        }

        MD5_Final(out, &c);
        printf("\n");
        //char md5sum[MD5_DIGEST_LENGTH*2];
        char* md5ptr = md5sum;
        for(n=0; n<MD5_DIGEST_LENGTH; n++)
                        md5ptr += sprintf(md5ptr, "%02x", out[n]);
    }
