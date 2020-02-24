/*
 *  Copyright (c) 2020, Peter Haag
 *  All rights reserved.
 *  
 *  Redistribution and use in source and binary forms, with or without 
 *  modification, are permitted provided that the following conditions are met:
 *  
 *   * Redistributions of source code must retain the above copyright notice, 
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the author nor the names of its contributors may be 
 *     used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 *  
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 *  POSSIBILITY OF SUCH DAMAGE.
 *  
 */

#include "config.h"

#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <string.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include "nfdump.h"
#include "nffile.h"
#include "output_util.h"

#define NumProtos	138
static char *protoList[NumProtos] = {
	"0",	  // 0 	masked out - no protocol info - set to '0'
	"ICMP",	  // 1 	Internet Control Message
	"IGMP",	  // 2	Internet Group Management
	"GGP",	  // 3	Gateway-to-Gateway
	"IPIP",	  // 4	IP in IP (encapsulation)
	"ST",	  // 5	Stream
	"TCP",	  // 6	Transmission Control
	"CBT",	  // 7	CBT
	"EGP",    // 8	Exterior Gateway Protocol
	"IGP",    // 9	any private interior gateway (used by Cisco for their IGRP)
	"BBN",	  // 10	BBN RCC Monitoring
	"NVPII",  // 11	Network Voice Protocol
	"PUP",	  // 12	PUP
	"ARGUS",  // 13	ARGUS
	"ENCOM",  // 14	EMCON
	"XNET",   // 15	Cross Net Debugger
	"CHAOS",  // 16	Chaos
	"UDP",	  // 17	User Datagram 
	"MUX",	  // 18	Multiplexing
	"DCN",	  // 19	DCN Measurement Subsystems
	"HMP",	  // 20	Host Monitoring
	"PRM",	  // 21	Packet Radio Measurement
	"XNS",	  // 22	XEROX NS IDP 
	"Trnk1",  // 23	Trunk-1
	"Trnk2",  // 24	Trunk-2
	"Leaf1",  // 25	Leaf-1
	"Leaf2",  // 26	Leaf-2
	"RDP",	  // 27	Reliable Data Protocol
	"IRTP",	  // 28	Internet Reliable Transaction
	"ISO-4",  // 29	ISO Transport Protocol Class 4
	"NETBK",  // 30	Bulk Data Transfer Protocol
	"MFESP",  // 31	MFE Network Services Protocol
	"MEINP",  // 32	MERIT Internodal Protocol
	"DCCP",	  // 33	Datagram Congestion Control Protocol
	"3PC",	  // 34	Third Party Connect Protocol
	"IDPR",	  // 35	Inter-Domain Policy Routing Protocol 
	"XTP",	  // 36	XTP
	"DDP",	  // 37	Datagram Delivery Protocol
	"IDPR",	  // 38	IDPR Control Message Transport Proto
	"TP++",	  // 39	TP++ Transport Protocol
	"IL",	  // 40	IL Transport Protocol
	"IPv6",	  // 41	IPv6
	"SDRP",	  // 42	Source Demand Routing Protocol
	"Rte6",   // 43	Routing Header for IPv6
	"Frag6",  // 44	Fragment Header for IPv6
	"IDRP",	  // 45	Inter-Domain Routing Protocol
	"RSVP",	  // 46	Reservation Protocol 
	"GRE",	  // 47	General Routing Encapsulation
	"MHRP",	  // 48	Mobile Host Routing Protocol
	"BNA",	  // 49	BNA
	"ESP",    // 50	Encap Security Payload 
	"AH",     // 51	Authentication Header
	"INLSP",  // 52	Integrated Net Layer Security  TUBA 
	"SWIPE",  // 53	IP with Encryption 
	"NARP",   // 54	NBMA Address Resolution Protocol
	"MOBIL",  // 55	IP Mobility
	"TLSP",   // 56	Transport Layer Security Protocol
	"SKIP",   // 57	SKIP
	"ICMP6",  // 58	ICMP for IPv6
	"NOHE6",  // 59	No Next Header for IPv6
	"OPTS6",  // 60	Destination Options for IPv6
	"HOST",   // 61	any host internal protocol
	"CFTP",   // 62	CFTP
	"NET",    // 63	any local network
	"SATNT",  // 64	SATNET and Backroom EXPAK
	"KLAN",   // 65	Kryptolan
	"RVD",    // 66	MIT Remote Virtual Disk Protocol
	"IPPC",   // 67	Internet Pluribus Packet Core
	"FS",     // 68	any distributed file system
	"SATM",   // 69	SATNET Monitoring 
	"VISA",   // 70	VISA Protocol
	"IPCV",   // 71	Internet Packet Core Utility
	"CPNX",   // 72	Computer Protocol Network Executive
	"CPHB",   // 73	Computer Protocol Heart Beat
	"WSN",    // 74	Wang Span Network
	"PVP",    // 75	Packet Video Protocol 
	"BSATM",  // 76	Backroom SATNET Monitoring
	"SUNND",  // 77	SUN ND PROTOCOL-Temporary
	"WBMON",  // 78	WIDEBAND Monitoring
	"WBEXP",  // 79	WIDEBAND EXPAK
	"ISOIP",  // 80	ISO Internet Protocol
	"VMTP",   // 81	VMTP
	"SVMTP",  // 82	SECURE-VMTP
	"VINES",  // 83	VINES
	"TTP",    // 84	TTP
	"NSIGP",  // 85	NSFNET-IGP
	"DGP",    // 86	Dissimilar Gateway Protocol
	"TCF",    // 87	TCF
	"EIGRP",  // 88	EIGRP
	"OSPF",   // 89	OSPFIGP
	"S-RPC",  // 90	Sprite RPC Protocol
	"LARP",   // 91	Locus Address Resolution Protocol
	"MTP",    // 92	Multicast Transport Protocol
	"AX.25",  // 93	AX.25 Frames
	"IPIP",	  // 94	IP-within-IP Encapsulation Protocol
	"MICP",   // 95	Mobile Internetworking Control Protocol
	"SCCSP",  // 96	Semaphore Communications Sec. Protocol
	"ETHIP",  // 97	Ethernet-within-IP Encapsulation
	"ENCAP",  // 98	Encapsulation Header
	"99",     // 99	any private encryption scheme
	"GMTP",   // 100	GMTP
	"IFMP",   // 101	Ipsilon Flow Management Protocol
	"PNNI",   // 102	PNNI over IP 
	"PIM",	  // 103	Protocol Independent Multicast
	"ARIS",   // 104	ARIS
	"SCPS",   // 105	SCPS
	"QNX",    // 106	QNX
	"A/N",    // 107	Active Networks
	"IPcmp",  // 108	IP Payload Compression Protocol
	"SNP",    // 109	Sitara Networks Protocol
	"CpqPP",  // 110	Compaq Peer Protocol
	"IPXIP",  // 111	IPX in IP
	"VRRP",   // 112	Virtual Router Redundancy Protocol
	"PGM",    // 113	PGM Reliable Transport Protocol
	"0hop",   // 114	any 0-hop protocol
	"L2TP",   // 115	Layer Two Tunneling Protocol
	"DDX",    // 116	D-II Data Exchange (DDX)
	"IATP",   // 117	Interactive Agent Transfer Protocol
	"STP",    // 118	Schedule Transfer Protocol
	"SRP",    // 119	SpectraLink Radio Protocol
	"UTI",    // 120	UTI
	"SMP",    // 121	Simple Message Protocol
	"SM",     // 122	SM
	"PTP",    // 123	Performance Transparency Protocol
	"ISIS4",  // 124	ISIS over IPv4
	"FIRE",   // 125	FIRE
	"CRTP",   // 126	Combat Radio Transport Protocol
	"CRUDP",  // 127	Combat Radio User Datagram
	"128",    // 128	SSCOPMCE
	"IPLT",   // 129	IPLP
	"SPS",    // 130	Secure Packet Shield 
	"PIPE",   // 131	Private IP Encapsulation within IP
	"SCTP",   // 132	Stream Control Transmission Protocol
	"FC",     // 133	Fibre Channel
	"134",    // 134	RSVP-E2E-IGNORE
	"MHEAD",  // 135	Mobility Header
	"UDP-L",  // 136	UDPLite
	"MPLS"    // 137	MPLS-in-IP 
};

#define NumZBFWProtocols	207
static char *ZBFWProtoList[NumZBFWProtocols] = {
	"unknown_proto",		//  0
	"tcp",					//  1
	"udp",					//  2
	"icmp",					//  3
	"ftp",					//  4
	"smtp",					//  5
	"esmtp",				//  6
	"realaudio",			//  7
	"netshow",				//  8
	"vdolive",				//  9
	"rpc",					//  10
	"msrpc",				//  11
	"rcmd",					//  12
	"exec",					//  13
	"login",				//  14
	"shell",				//  15
	"streamworks",			//  16
	"cuseeme",				//  17
	"http",					//  18
	"sqlnet",				//  19
	"tftp",					//  20
	"rtsp",					//  21
	"sip",					//  22
	"mgcp",					//  23
	"skinny",				//  24
	"dns",					//  25
	"h323",					//  26
	"h245",					//  27
	"h225",					//  28
	"h225_ras",				//  29
	"pop3",					//  30
	"imap",					//  31
	"ymsgr",				//  32
	"aim",					//  33
	"msnmgr",				//  34
	"test",					//  35
	"netbios ns",			//  36
	"netbios dgm",			//  37
	"netbios ssn",			//  38
	"gtvp0",				//  39
	"gtpv1",				//  40
	"test66",				//  41
	"test64",				//  42
	"gtp data",				//  43
	"granular",				//  44
	"ctrl max",				//  45
	"ftp data",				//  46
	"realaudio data",		//  47
	"netshow data",			//  48
	"vdolive data",			//  49
	"rpc data",				//  50
	"msrpc data",			//  51
	"rcmd data",			//  52
	"streamworks data",		//  53
	"cuseeme data",			//  54
	"sqlnet data",			//  55
	"tftp data",			//  56
	"rtsp data",			//  57
	"sip rtp data",			//  58
	"sip rtcp data",		//  59
	"mgcp data",			//  60
	"skinny data",			//  61
	"h323  rtp audio",		//  62
	"h323 rtcp audio",		//  63
	"h323 rtp video",		//  64
	"h323 rtcp video",		//  65
	"h323 rtp data",		//  66
	"h323 rtcp data",		//  67
	"test data",			//  68
	"max prot w stats",		//  69
	"telnet",				//  70
	"tacacs",				//  71
	"https",				//  72
	"gopher",				//  73
	"finger",				//  74
	"kerberos",				//  75
	"pop2",					//  76
	"nntp",					//  77
	"snmp",					//  78
	"ldap",					//  79
	"ms sql",				//  80
	"sybase sql",			//  81
	"nfs",					//  82
	"lotusnote",			//  83
	"sap",					//  84
	"echo",					//  85
	"discard",				//  86
	"daytime",				//  87
	"netstat",				//  88
	"ssh",					//  89
	"time",					//  90
	"tacacs ds",			//  91
	"bootps",				//  92
	"bootpc",				//  93
	"dnsix",				//  94
	"rtelnet",				//  95
	"ident",				//  96
	"sqlserv",				//  97
	"ntp",					//  98
	"pwdgen",				//  99
	"cisco fna",			//  100
	"cisco tna",			//  101
	"cisco sys",			//  102
	"sqlsrv",				//  103
	"snmptrap",				//  104
	"rsvd",					//  105
	"send",					//  106
	"xdmcp",				//  107
	"bgp",					//  108
	"irc",					//  109
	"qmtp",					//  110
	"ipx",					//  111
	"dbase",				//  112
	"imap3",				//  113
	"rsvp tunnel",			//  114
	"hp collector",			//  115
	"hp managed node",		//  116
	"hp alarm mgr",			//  117
	"microsoft ds",			//  118
	"creativeserver",		//  119
	"creativepartnr",		//  120
	"appleqtc",				//  121
	"igmpv3lit",			//  122
	"isakmp",				//  123
	"biff",					//  124
	"who",					//  125
	"syslog",				//  126
	"router",				//  127
	"ncp",					//  128
	"timed",				//  129
	"irc serv",				//  130
	"uucp",					//  131
	"syslog conn",			//  132
	"sshell",				//  133
	"ldaps",				//  134
	"dhcp failover",		//  135
	"msexch routing",		//  136
	"entrust svcs",			//  137
	"entrust svc handler",	//  138
	"nisco tdp",			//  139
	"webster",				//  140
	"gdoi",					//  141
	"iscsi",				//  142
	"cddbp",				//  143
	"ftps",					//  144
	"telnets",				//  145
	"imaps",				//  146
	"ircs",					//  147
	"pop3s",				//  148
	"socks",				//  149
	"kazaa",				//  150
	"ms sql m",				//  151
	"ms sna",				//  152
	"wins",					//  153
	"ica",					//  154
	"orasrv",				//  155
	"rdb dbs disp",			//  156
	"vqp",					//  157
	"icabrowser",			//  158
	"kermit",				//  159
	"rsvp encap",			//  160
	"l2tp",					//  161
	"pptp",					//  162
	"h323gatestat",			//  163
	"r winsock",			//  164
	"radius",				//  165
	"hsrp",					//  166
	"net8 cman",			//  167
	"oracle em vp",			//  168
	"oraclenames",			//  169
	"oracle",				//  170
	"cisco svcs",			//  171
	"cisco net mgmt",		//  172
	"stun",					//  173
	"tr rsrb",				//  174
	"ddns v3",				//  175
	"ace svr",				//  176
	"giop",					//  177
	"ttc",					//  178
	"ipass",				//  179
	"clp",					//  180
	"citriximaclient",		//  181
	"sms",					//  182
	"citriximaclient",		//  183
	"realsecure",			//  184
	"lotussmtap",			//  185
	"cifs",					//  186
	"ms dotnetster",		//  187
	"tarantella",			//  188
	"fcip port",			//  189
	"ssp",					//  190
	"iscsi target",			//  191
	"mysql",				//  192
	"ms cluster net",		//  193
	"ldap admin",			//  194
	"802.11 iapp",			//  195
	"oem agent",			//  196
	"rtc pm port",			//  197
	"dbcontrol agent",		//  198
	"ipsec msft",			//  199
	"sip tls",				//  200
	"pcanywheredata",		//  201
	"pcanywherestat",		//  202
	"x11",					//  203
	"ircu",					//  204
	"n2h2server",			//  205
	"h323callsigalt",		//  206
	"h225ras mcast",		//  207
};

char *L7ProtoString(int l7_proto_id) {
		return ZBFWProtoList[l7_proto_id];
	}

char *ProtoString(uint8_t protoNum) {
static char s[16];

	if ( protoNum >= NumProtos ) {
		snprintf(s,15,"%-5i", protoNum );
		s[15] = '\0';
		return s;
	} else {
		return protoList[protoNum];
	}

} // End of ProtoString

int ProtoNum(char *protoString) {
int len;

	if ( (len = strlen(protoString)) >= 6 )
		return -1;

	for ( int i=0; i<NumProtos; i++ ) {
		if ( strncasecmp(protoString,protoList[i], len) == 0 && 
			( strlen(protoList[i]) == len) )
			return i;
	}

	return -1;

} // End of ProtoNum

char *FlagsString(uint16_t flags) {
static char string[16];

	string[0] = flags & 128 ? 'C' : '.';	// Congestion window reduced -  CWR
	string[1] = flags &  64 ? 'E' : '.';	// ECN-Echo
	string[2] = flags &  32 ? 'U' : '.';	// Urgent
	string[3] = flags &  16 ? 'A' : '.';	// Ack
	string[4] = flags &   8 ? 'P' : '.';	// Push
	string[5] = flags &   4 ? 'R' : '.';	// Reset
	string[6] = flags &   2 ? 'S' : '.';	// Syn
	string[7] = flags &   1 ? 'F' : '.';	// Fin
	string[8] = '\0';
	
	return string;
} // End of FlagsString


void CondenseV6(char *s) {
size_t len = strlen(s);
char	*p, *q;

	if ( len <= 16 )
		return;

	// orig:      2001:620:1000:cafe:20e:35ff:fec0:fed5 len = 37
	// condensed: 2001:62..e0:fed5
	p = s + 7;
	*p++ = '.';
	*p++ = '.';
	q = s + len - 7;
	while ( *q ) { 
		*p++ = *q++; 
	}
	*p = 0;

} // End of CondenseV6

char *FwEventString(int event) {

	switch(event) {
#ifdef JUNOS
		case 0:
			return "IGNORE";
			break;
		case 1:
		case 4:
		case 6:
		case 8:
		case 12:
			return "CREATE";
			break;
		case 2:
		case 5:
		case 7:
		case 9:
		case 13:
			return "DELETE";
			break;
		case 3:
		case 10:
			return "EXHAUSTED";
			break;
		case 11:
			return "QUOTA EXCEED";
			break;
		case 14:
			return "NAT PORT ALLOC";
			break;
		case 15:
			return "NAT PORT RELEASE";
			break;
		case 16:
			return "NAT PORT ACTIVE";
			break;
#else
		case 0:
			return "IGNORE";
			break;
		case 1:
			return "CREATE";
			break;
		case 2:
			return "DELETE";
			break;
		case 3:
			return "DENIED";
			break;
		case 4:
			return "ALERT";
			break;
		case 5:
			return "UPDATE";
			break;
#endif
		default:
			return "UNKNOW";
	}			

} // End of FwEventString

char *EventString(int event) {

	switch(event) {
		case 0:
			return "INVALID";
			break;
		case 1:
			return "ADD";
			break;
		case 2:
			return "DELETE";
			break;
		default:
			return "UNKNOW";
	}			

} // End of EventString

char *EventXString(int xevent) {
static char s[16];

	switch( xevent) {
		case 0:
			return "Ignore";
			break;
		case 1001:
			return "I-ACL";
			break;
		case 1002:
			 return "E-ACL";
			break;
		case 1003:
			 return "Adap";
			break;
		case 1004:
			return "No Syn";
			break;
		default:
			snprintf(s,15,"%u",xevent);
			s[15] = '\0';
			return s;
	}

	// not reached
} // End of EventXString
