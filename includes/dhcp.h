#include <stdint.h>
#include <endian.h>

#define DHCP_HLEN 236
#define DHCP_MAGIC_1 0x63
#define DHCP_MAGIC_2 0x82
#define DHCP_MAGIC_3 0x53
#define DHCP_MAGIC_4 0x63

#define DHCP_Pad 0
#define DHCP_Subnet_Mask 1
// Time Offset in
#define DHCP_Time_Offset 2
#define DHCP_Router_Address 3
#define DHCP_Time_Server 4
#define DHCP_IEN_116_Name_Server 5
#define DHCP_Domain_Name_Server 6
// Logging_Server addresses
#define DHCP_Log_Server 7
#define DHCP_Cookie_Server 8
#define DHCP_LPR_Server 9
#define DHCP_Impress_Server 10
#define DHCP_RLP_Server 11
// Hostname
#define DHCP_Hostname 12
// Size of boot file in 512
#define DHCP_Boot_File_Size 13
// Client to dump and name
#define DHCP_Merit_Dump_File 14
#define DHCP_Domain_Name 15
#define DHCP_Swap_Server 16
// Path name for root disk
#define DHCP_Root_Path 17
#define DHCP_Bootp_Extensions_Path 18
#define DHCP_IP_Forward_Enable 19
#define DHCP_Source_Route_Enable 20
// Routing Policy Filters
#define DHCP_Policy_Filter 21
#define DHCP_Max_Datagram_Reassembly_Sz 22
#define DHCP_Default_IP_TTL 23
#define DHCP_Path_MTU_Aging_Timeout 24
#define DHCP_Path_MTU_Plateau_Table 25
#define DHCP_Interface_MTU_Size 26
#define DHCP_All_Subnets_Are_Local 27
#define DHCP_Broadcast_Address 28
#define DHCP_Perform_Mask_Discovery 29
#define DHCP_Provide_Mask_To_Others 30
#define DHCP_Perform_Router_Discovery 31
#define DHCP_Router_Solicitation_Address 32
// first is destination address, second is router.
#define DHCP_Static_Routes 33
#define DHCP_Trailer_Encapsulation 34
#define DHCP_ARP_Cache_Timeout 35
#define DHCP_Ethernet_Encapsulation 36
#define DHCP_Default_TCP_TTL 37
#define DHCP_Keep_Alive_Interval 38
#define DHCP_Keep_Alive_Garbage 39
#define DHCP_NIS_Domain_Name 40
#define DHCP_NIS_Servers 41
#define DHCP_NTP_Servers 42
// N Vendor Specific Information
#define DHCP_Vendor 43 // tlv
#define DHCP_NETBIOS_Name_Servers 44
#define DHCP_NETBIOS_Dgm_Dist_Servers 45
#define DHCP_NETBIOS_Node_Type 46
// N NETBIOS Scope
#define DHCP_NETBIOS 47
#define DHCP_X_Window_Font_Server 48
#define DHCP_X_Window_Display_Mgr 49
#define DHCP_Requested_IP_Address 50
#define DHCP_IP_Address_Lease_Time 51
// Overload "sname" or "file"
#define DHCP_Overload 52
#define DHCP_Message_Type 53
#define DHCP_Server_Identifier 54

//  of 1_ numbers indicating which options the client
// would like to see in the response.
#define DHCP_Parameter_Request_List 55
#define DHCP_Error_Message 56
#define DHCP_Maximum_Msg_Size 57
#define DHCP_Renewal_Time 58
#define DHCP_Rebinding_Time 59
#define DHCP_Vendor_Class_Identifier 60

// Client Identifier
// First  is DHCP_Hardware_Type, rest are type_specific data,
// e.g. MAC address.
#define DHCP_Client_Identifier 61
#define DHCP_Netware_Domain_Name 62
#define DHCP_Netware_Sub_Options 63
#define DHCP_NIS_Client_Domain_Name 64
#define DHCP_NIS_Server_Address 65
#define DHCP_TFTP_Server_Name 66
#define DHCP_Boot_File_Name 67
// Home Agent Addresses
#define DHCP_Home_Agent_Address 68
#define DHCP_SMTP_Server_Address 69
#define DHCP_POP3_Server_Address 70
#define DHCP_NNTP_Server_Address 71
#define DHCP_WWW_Server_Address 72
#define DHCP_Finger_Server_Address 73
#define DHCP_IRC_Server_Address 74
#define DHCP_StreetTalk_Server_Address 75
#define DHCP_STDA_Server_Address 76
// User Class Information
#define DHCP_User_Class 77
// directory agent information
#define DHCP_Directory_Agent 78
// service location agent scope
#define DHCP_Service_Scope 79
// Rapid Commit
#define DHCP_Rapid_Commit 80
// Fully Qualified Domain Name
#define DHCP_Client_FQDN 81
// Relay Agent Information
#define DHCP_Relay_Agent_Information 82 // tlv
// Internet Storage Name Service
#define DHCP_iSNS 83
// Novell Directory Services
#define DHCP_NDS_Servers 85
// Novell Directory Services
#define DHCP_NDS_Tree_Name 86
// Novell Directory Services
#define DHCP_NDS_Context 87
// Authentication
#define DHCP_Authentication 90

#define DHCP_Client_Last_Txn_Time 91

#define DHCP_associated_ip 92
// Client System Architecture
#define DHCP_Client_System 93
// Client Network Device Interface
#define DHCP_Client_NDI 94
// Lightweight Directory Access Protocol
#define DHCP_LDAP 95
// UUID/GUID_based Client Identifier
#define DHCP_UUID_GUID 97
// Open Group's User Authentication
#define DHCP_User_Auth 98
// NetInfo Parent_Server Address
#define DHCP_Netinfo_Address 112
// NetInfo Parent_Server Tag
#define DHCP_Netinfo_Tag 113
// URL
#define DHCP_URL 114
// DHCP Auto_Configuration
#define DHCP_Auto_Config 116
// Name Service Search
#define DHCP_Name_Service_Search 117
// Subnet Selection Option
#define DHCP_Subnet_Selection_Option 118
// DNS domain serach list
#define DHCP_Domain_Search 119
// SIP_Servers DHCP Option
#define DHCP_SIP_Servers_DHCP_Option 120
// Classless Static Route Option
#define DHCP_Classless_Static_Route 121
// CableLabs Client Configuration
#define DHCP_CCC 122
// 16 GeoConf Option
#define DHCP_GeoConf_Option 123

// Vendor Class
//
//  name that defines the vendor space used for the TLV's
// in option 125.
//
#define DHCP_V_I_Vendor_Class 124
// Vendor_Specific
#define DHCP_V_I_Vendor_Specific 125 // tlv
// 6 s: E4:45:74:68:00:00
#define DHCP_Etherboot 128
// (for IP Phone software load)
#define DHCP_TFTP_Server_IP_Address 128

#define DHCP_Call_Server_IP_address 129

#define DHCP_Ethernet_Interface 130

#define DHCP_Vendor_Discrimination_Str 130

#define DHCP_Remote_Stats_Svr_IP_Address 131

#define _op55 132

#define DHCP_IEEE_802_1P_VLAN_ID 133

#define DHCP_Diffserv_Code_Point 134

#define DHCP_HTTP_Proxy 135

#define DHCP_Cisco_TFTP_Server_IP_Addresses 150

#define DHCP_End_Of_Options 255

// Message type 53 values
#define DHCP_Discover 1
#define DHCP_Offer 2
#define DHCP_Request 3
#define DHCP_Decline 4
#define DHCP_Ack 5
#define DHCP_NAK 6
#define DHCP_Release 7
#define DHCP_Inform 8
#define DHCP_Force_Renew 9

// parameter list 55

#define DHCP_Private_Classless_Static_Route_Microsoft 249
#define DHCP_Private_Proxy_autodiscovery 252

char DHCP_PRL[136][50] = {
    "Undefined",                            //   0
    "Subnet Mask",                          //	 1
    "Time Offset",                          //	 2
    "Router Address",                       //	 3
    "Time Server",                          //	 4
    "IEN 116 Name Server",                  //   5
    "Domain Name Server",                   //	 6
    "Log Server",                           //	 7
    "Quotes Server",                        //	 8
    "LPR Server	",                          //	 9
    "Impress Server",                       //	 10
    "RLP Server",                           //	 11
    "Hostname",                             //	 12
    "Boot File Size",                       //	 13
    "Merit Dump File",                      //	 14
    "Domain Name",                          //	 15
    "Swap Server",                          //	 16
    "Root Path",                            //	 17
    "Bootp Extensions Path",                //   18
    "IP Forward Enable",                    //	 19
    "Source Route Enable",                  //   20
    "Policy Filter",                        //	 21
    "Max Datagram Reassembly Sz",           //   22
    "Default IP TTL	23",                    //   23
    "Path MTU Aging Timeout",               //   24
    "Path MTU Plateau Table",               //   25
    "Interface MTU Size",                   //	 26
    "All Subnets Are Local",                //   27
    "Broadcast Address",                    //	 28
    "Perform Mask Discovery",               //   29
    "Provide Mask To Others",               //   30
    "Perform Router Discovery",             //   31
    "Router Solicitation Address",          //   32
    "Static Route" ,                        //	 33
    "Trailer Encapsulation",                //   34
    "ARP Cache Timeout",                    //	 35
    "Ethernet Encapsulation",               //   36
    "Default TCP TTL",                      //	 37
    "Keep Alive Interval",                  //   38
    "Keep=Alive Garbage",                   //   39
    "NIS Domain Name",                      //	 40
    "NIS Servers",                          //	 41
    "NTP Servers",                          //	 42
    "Vendor-Specific Information",          //	 43
    "NETBIOS over TCP/IP Name Servers",     //   44
    "NETBIOS Dgm Dist Servers",             //   45
    "NETBIOS over TCP/IP Node Type",        //	 46
    "NETBIOS over TCP/IP Scope",            //	 47
    "X Window Font Server",                 //   48
    "X Window Display Mgr",                 //   49
    "Requested IP Address",                 //   50
    "IP Address Lease Time",                //   51
    "Overload",                             //	 52
    "Message Type",                         //	 53
    "Server Identifier",                    //   54
    "Parameter Request List",               //   55
    "Error Message",                        //	 56
    "Maximum Msg Size",                     //   57
    "Renewal Time",                         //	 58
    "Rebinding Time",                       //	 59
    "Class Identifier",                     //	 60
    "Client Identifier",                    //	 61
    "Netware Domain Name",                  //   62
    "Netware Sub Options",                  //   63
    "NIS Client Domain Name",               //   64
    "NIS Server Address",                   //	 65
    "TFTP Server Name",                     //	 66
    "Boot File Name",                       //	 67
    "Home Agent Address",                   //	 68
    "SMTP Server Address",                  //   69
    "POP3 Server Address",                  //   70
    "NNTP Server Address",                  //   71
    "WWW Server Address",                   //	 72
    "Finger Server Address",                //   73
    "IRC Server Address",                   //	 74
    "StreetTalk Server Address",            //   75
    "STDA Server Address",                  //   76
    "User Class",                           //	 77
    "Directory Agent",                      //	 78
    "Service Scope",                        //	 79
    "Rapid Commit",                         //	 80
    "Client FQDN",                          //	 81
    "Relay Agent Information",              //   82
    "iSNS",                                 //	 83
    "Undefined",                            //   84
    "NDS Servers",                          //	 85
    "NDS Tree Name",                        //	 86
    "NDS Context",                          //   87
    "Undefined",                            //   88
    "Undefined",                            //   89
    "Authentication",                       //	 90
    "Client Last Txn Time",                 //   91
    "associated ip",                        //	 92
    "Client System",                        //	 93
    "Client NDI",                           //	 94
    "LDAP",                                 //	 95
    "Undefined",                            //   96
    "UUID/GUID",                            // 	 97
    "User Auth",                            //	 98
    "Undefined",                            //   99
    "Undefined",                            //   100
    "Undefined",                            //   101
    "Undefined",                            //   102
    "Undefined",                            //   103
    "Undefined",                            //   104
    "Undefined",                            //   105
    "Undefined",                            //   106
    "Undefined",                            //   107
    "Undefined",                            //   108
    "Undefined",                            //   109
    "Undefined",                            //   110
    "Undefined",                            //   111
    "Netinfo Address",                      //	 112
    "Netinfo Tag",                          //	 113
    "URL",                                  //	 114
    "Undefined",                            //   115
    "Auto Config",                          // 	 116
    "Name Service Search",                  //   117
    "Subnet Selection Option",              //   118
    "Domain Search",                        //	 119
    "SIP Servers Option",                   //   120
    "Classless Static Route",               //   121
    "CCC",                                  //	 122
    "GeoConf Option",                       //   123
    "V I Vendor Class",                     //	 124
    "V I Vendor Specific",                  //   125
    "Undefined",                            //   126
    "Undefined",                            //   127
    "TFTP Server IP Address",               //   128
    "Call Server IP address",               //   129
    "Ethernet Interface",                   //   130
    "Remote Stats Svr IP Address",          //   131
    "IEEE 802.1P VLAN ID",                  //   132
    "IEEE 802.1Q L2 Priority",              //   133
    "Diffserv Code Point",                  //   134
    "HTTP Proxy",                           //   135
};

typedef struct _dhcp_file
{
    char file[128];
} dhcp_file_;

typedef struct _dhcp_sname
{
    char sname[64];
} dhcp_sname_;

typedef struct _dhcp_chaddr
{
    char chaddr[16];
} dhcp_chaddr_;

typedef struct _dhcp_head
{
    uint8_t dhcp_op;
    uint8_t dhcp_htype;
    uint8_t dhcp_hlen;
    uint8_t dhcp_hops;
    uint32_t dhcp_xid;
    uint16_t dhcp_secs;
    uint16_t dhcp_flags;
    uint32_t dhcp_ciaddr;
    uint32_t dhcp_yiaddr;
    uint32_t dhcp_siaddr;
    uint32_t dhcp_giaddr;
    dhcp_chaddr_ dhcp_chaddr;
    dhcp_sname_ dhcp_sname;
    dhcp_file_ dhcp_file;
} dhcp_head;
