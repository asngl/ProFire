# ProFire
Prolog based firewall system
The Creators:
Yashdeep Gupta-2017A7PS0114P
Ayush Singhal- 2017A7PS0116P
Saksham GUpta- 2017A7PS0218P


Adding Rules:
        To add new rules , you can add the following line to the start of firewall_assignment.pl
 add_rule(StringArgument).
        StringArgument takes the form as “accept/reject/drop FirewallClause”.
Modifying Default Operation:
The default setting whether to accept, drop or reject can be modified by changing the defaultRejected, defaultDropped and defaultAccepted clauses at the top of the file, to true or false, as needed.
Running the program:
In the SWI Prolog console ,start with the command
consult(“filepath”).
to load the file into memory.You may then use the command specified in the next section to verify whether a given packet would be rejected ,dropped or accepted.
Checking for a packet:
check_packet(AdapterName,VID,ProtoID,IPType,SrcIP,DstIP,ProtoType,Dginfo1,Dginfo2).
    This command can be used to verify whether a packet will be accepted, rejected or dropped based on the rules specified by the user. Once the console produces an output, the user may press “;” to skip the top-level rule and verify the packet considering other rules that apply.


AdapterName: Name of the adapter that is being used , can be any letter from “A”-”P”.
VID:       Can be any decimal(base 10) number.
ProtoID: Can be any hexadecimal number.
IPType:  Can be “ip” or “ipv6” as required.
SrcIP:    Denotes the IP address of the source. 
DstIP:    Denotes the IP address of the destination.
ProtoType: Can be “tcp”,”udp”,”icmp” or ”icmpv6”.
Dginfo1,Dginfo2: Denotes sourcePort and destinationPort respectively when ProtoType=”tcp” or “udp”.Denotes protocolType and protocolCode respectively when ProtoType=”icmp” or “icmpv6”. 


Rule Syntax:
1. All IP addresses must be specified in the format A.B.C.D , where A,B,C,D are base 10 numbers in the range 0-255.
2. Prototype-id must always be specified in hexadecimal format and the digits a-f must be in lowercase.
3.           Dginfo1 and Dginfo2 must be in base 10 format. 


Sample Input and Output:
Sample Input
1)check_packet("A","12","12","ip","1.1.1.1","1.1.1.1","tcp","12","12").


2)check_packet("A","12","12","ipv6","FF01:0:0:0:0:0:0:101","FF01:0:0:0:0:0:0:102","icmp","12","12").


3)check_packet("D","2","0x86dd","ip","192.168.1.1/2","192.168.1.1/2","udp","65528","65528").


Sample Output
1)Packet Dropped
true ;
Packet Dropped
true ;
No rules apply.Rejected.
true ;
No rules apply.Dropped
true ;
false.


2)Packet Rejected
true ;
Packet Dropped
true ;
Packet Dropped
true ;
Packet Dropped
true ;
Packet Dropped
true ;
No rules apply.Rejected.
true ;
No rules apply.Dropped
true ;
false.


3)Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
Packet Accepted
true ;
No rules apply.Rejected.
true ;
No rules apply.Dropped
true ;
false.
