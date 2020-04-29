/*
 * dns_server.c
 *
 *  Created on: Apr 26, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdbool.h>
#include<time.h>

#include "dns.h"

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr server;

	int port = 53; //the default port of DNS service


	//to keep the information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	query queries[ANS_SIZE];


	if(argc == 2)
	{
		port = atoi(argv[1]); //if we need to define the DNS to a specific port
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	int enable = 1;

	if(sockfd <0 )
	{
		perror("socket creation error");
		exit_with_error("Socket creation failed");
	}

	//in some operating systems, you probably need to set the REUSEADDR
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	}

	//for v4 address
	struct sockaddr_in *server_v4 = (struct sockaddr_in*)(&server);
	server_v4->sin_family = AF_INET;
	server_v4->sin_addr.s_addr = htonl(INADDR_ANY);
	server_v4->sin_port = htons(port);

	//bind the socket
	if(bind(sockfd, &server, sizeof(*server_v4))<0){
		perror("Binding error");
		exit_with_error("Socket binding failed");
	}

	printf("The dns_server is now listening on port %d ... \n", port);
	//print out
	uint8_t buf[BUF_SIZE], send_buf[BUF_SIZE]; //receiving buffer and sending buffer
	struct sockaddr remote;
	int n;
	socklen_t addr_len = sizeof(remote);
	struct sockaddr_in *remote_v4 = (struct sockaddr_in*)(&remote);

	/****************** Written by Dongchen He ************/
	while(1)
	{
		//an infinite loop that keeps receiving DNS queries and send back a reply
		//complete your code here
		
		//receiving queries
		memset(buf, 0, BUF_SIZE);
		n = recvfrom(sockfd, (char*)buf, BUF_SIZE, 0, &remote, &addr_len);
		//n is the packet length

		printf("Received query from %s\n", inet_ntoa(remote_v4->sin_addr));
		
		parse_dns_query(buf, queries, answers, auth, addit);	
		
		memcpy(send_buf, buf, n);

		//modify the header section
		dns_header *dns = (dns_header*)send_buf;
		dns->qr = 1;
		dns->an_count = dns->qd_count;

		//build answer sections
		uint8_t *p = send_buf + n;
		for(int i=0; i<ntohs(dns->qd_count); i++){
			get_dns_name(p, queries[i].qname);
			n += strlen((char*)p) + 1;
			p = send_buf + n;

			r_element *re = (r_element*)p;
			re->type = htons(TYPE_A);
			re->_class = htons(CLASS_IN);
			re->ttl = htonl(300);
			re->rdlength = htons(4);

			//rdata
			n += sizeof(r_element);
			p = send_buf + n;
			inet_pton(AF_INET, "10.10.10.10", p);
			n += 4;
			p += 4;
		}
		
	sendto(sockfd, (char*)send_buf, n, 0, &remote, addr_len);

	}
}
