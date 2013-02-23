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
	double etherStandardDev;
	double ipMean;
	double ipStandardDev;
	double tcpMean;
	double tcpStandardDev;
}stream;

/***********************************
 * Prototypes
 **********************************/
void displayOutput(int count, packet* packetStream, stream stream);
void f_argparser(int argc, char **argv, argparse* arg_vars);
int countPackets(pcap_t* handle);
void setPackets(pcap_t* handle, packet* packetStream, argparse arguments);
double calcEtherMean(int count, packet* packetStream);


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
            //Opening a pcap handle
            handle = pcap_open_offline(arguments.filename, errbuf);
        }
        /**********************************
         * Main Operation
         *********************************/
        //Grabbing total count of packets
        int count = countPackets(handle);
        //Allocating array of packets of count #
        packet packetStream[count];
        //Filling out packet array
        setPackets(handle, packetStream, arguments);

        //Struct used to hold stream information
        stream stream;
        memset(&stream, 0, sizeof(stream));
        //Calculations for Stream
        stream.etherMean = calcEtherMean(count, packetStream);



        /*****************
         * Printing Output
         ****************/
        displayOutput(count, packetStream, stream);


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
            if(arguments.verbosemode == 1){
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
            }


            count++;
        }

        //Rewinding Pcap File
        FILE* pcapFile = pcap_file(handle);
		rewind( pcapFile );
		fseek( pcapFile, 24, SEEK_SET );

    }

    /******************************************
     * Calculates the ethernet mean
     * of bytes in the entire stream
     * @param count - Number of packets
     * @param packetStream - array of packets
     * @return the mean of ethernet in bytes
     *****************************************/
    double calcEtherMean(int count, packet* packetStream){
    	int mean = 0;
    	int i;
    	for(i= 0; i < count; i++){
    		mean += packetStream[i].etherSize;
    	}
    	mean = mean / count;
    	return mean;
    }



    /************************************************
     * Displays output at the end of the program
     * @param count - Number of Packets in the stream
     ************************************************/
    void displayOutput(int count, packet* packetStream, stream stream){
    	printf("*************************\n");
    	printf("\tOutput:\n");
    	printf("*************************\n");
    	printf("Total Packet Count: %i\n", count);
    	printf("Stream Discriminators:\n");
    	printf("\tEthernet Mean: %.2f", stream.etherMean);
    	printf("\n\n\n");
    }
