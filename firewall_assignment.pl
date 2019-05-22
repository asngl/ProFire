/*
                     Prolog Project on Firewall Rules presented by-
                     Name                Id
                     Yashdeep Gupta 2017A7PS0114P
                     Ayush Singhal 2017A7PS0116P
                     Saksham Gupta 2017A7PS0218P
*/

/*Sample Input
check_packet("A","12","12","ip","1.1.1.1","1.1.1.1","tcp","12","12").
check_packet("A","12","12","ipv6","FF01:0:0:0:0:0:0:101","FF01:0:0:0:0:0:0:102","icmp","12","12").
check_packet("D","2","0x86dd","ip","192.168.1.1/2","192.168.1.1/2","udp","65528","65528").


                     */
/*Sample Output
Packet Dropped
true ;
Packet Dropped
true ;
No rules apply.Rejected.
true ;
No rules apply.Dropped
true ;
false.

Packet Rejected
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
Packet Accepted
true ;
No rules apply.Rejected.
true ;
No rules apply.Dropped
true ;
false.


                     */




/*Rules Initialisor For Different Firewall rules*/



add_rule("drop adapter A-C").
add_rule("accept adapter D").
add_rule("reject adapter E,G").
add_rule("reject ether vid 1 proto 0x0800").
add_rule("accept ether vid 2 proto 0x86dd").
add_rule("drop ether vid 3-999 proto 0x1800,0x85dd").
add_rule("accept ip addr 192.168.1.1/2").
add_rule("reject ip addr 192.168.10.0-192.168.10.255").
add_rule("drop ip addr 192.168.10.1/24").
add_rule("drop ipv6 addr FF01:0:0:0:0:0:0:101").
add_rule("accept ipv6 addr 12AB:0:0:CD30::/60").
add_rule("reject ipv6 addr FF01::102-FF01:0:0:0:0:0:0:200").
add_rule("drop tcp src port 65530").
add_rule("reject udp dst port 0-2").
add_rule("accept udp dst port !(3 - 65525) src port 65528").
add_rule("accept icmp type 45").
add_rule("reject icmp code 33").
add_rule("drop icmp type 1 code 2").
add_rule("drop icmpv6 type 656>").
add_rule("accept icmpv6 code 65656").
add_rule("reject icmpv6 type 7 code 13").
add_rule("reject ether vid 13 proto 0xface").
add_rule("reject icmp type 35 code 41").
add_rule("reject ipv6 src addr 1234:2345::32").


defaultRejected:-true.
defaultAccepted:-false.
defaultDropped:-true.
/*---------------------Utility Functions-----------------------------------------------*/

/* Range is of the format A,B,C */
alphabet_commalist_contains(Range,Character):-
    split_string(Range,",","",L),
    member(Character,L).

/* Range is of the form A-D */

alphabet_rangelist_contains(Range,Character):-
    split_string(Range,"-","",L),
    L=[E1,E2],
    char_code(E1,C1),
    char_code(E2,C2),
    char_code(Character,C),
    C1=<C,
    C=<C2.

/*Range is of the form 1-4*/
number_rangelist_contains(Range,Number):-
    split_string(Range,"-","",L),
    L=[E1,E2],
    number_string(C1,E1),
    number_string(C2,E2),
    number_string(C,Number),
    C1=<C,
    C=<C2.

/*Checks whether X is a substring of S*/
substring(X,S) :-
    append(_,T,S),
    append(X,_,T),
    X \= []
    .
/*Range is of the form !(1-4)*/
number_not_rangelist_contains(Range,Number):-
    substring("!",Range),
    string_concat("!(",Range2,Temp),
    string_concat(Temp,")",Range),
    not(number_rangelist_contains(Range2,Number)).

/*Checks whether Str2 is a part of Str1, Str1 can be a range or a comma list*/
ip_contains(Str1,Str2):-
    ((Str1=Str2;string_concat(Str1,"/",Temp),string_concat(Temp,_,Str2);string_concat(Str2,"/",Temp2),string_concat(Temp2,_,Str1));alphabet_commalist_contains(Str1,Str2);ip_range_contains(Str1,Str2)).

/*When range is of the form x.x.x.y-x.x.x.z*/
ip_range_contains(Range,IP):-
    split_string(Range,"-","",[E1|[E2]]),
    split_string(E1,".","",[H1|[H2|[H3|[N1]]]]),
    split_string(E2,".","",[H1|[H2|[H3|[N2]]]]),
    split_string(IP,".","",[H1|[H2|[H3|[N3]]]]),
    number_string(Num1,N1),
    number_string(Num2,N2),
    number_string(Num3,N3),
    Num1=<Num3,
    Num3=<Num2.

/*Removes extra characters from ip such as four simultaneous zeroes and extra colons*/
reduce_ipv6(Str1,Str2):-
    re_replace(":0000:","::",Str1,Temp1),
    re_replace(":0000:","::",Temp1,Temp2),
    re_replace(":0000:","::",Temp2,Temp3),
    re_replace(":0000:","::",Temp3,Temp4),
    re_replace(":0000:","::",Temp4,Temp5),
    re_replace(":0000:","::",Temp5,Temp6),
    re_replace(":0000:","::",Temp6,Temp7),
    re_replace(":0000:","::",Temp7,Temp8),
    re_replace(":0:","::",Temp8,Temp9),
    re_replace(":0:","::",Temp9,Tempq),
    re_replace(":0:","::",Tempq,Tempw),
    re_replace(":0:","::",Tempw,Tempe),
    re_replace(":0:","::",Tempe,Tempr),
    re_replace(":0:","::",Tempr,Tempt),
    re_replace(":0:","::",Tempt,Tempy),
    re_replace(":0:","::",Tempy,Tempu),
    re_replace(":::","::",Tempu,Tempi),
    re_replace(":::","::",Tempi,Tempo),
    re_replace(":::","::",Tempo,Tempp),
    re_replace(":::","::",Tempp,Tempa),
    re_replace(":::","::",Tempa,Temps),
    re_replace(":::","::",Temps,Tempd),
    re_replace(":::","::",Tempd,Tempf),
    re_replace(":::","::",Tempf,Str2).

/*Extracts the last number from ip of type ipv6*/
ipv6_lastnum(String,Number):-
    split_string(String,":",":",L),
    last(L,Last),
    (
        (
            Last="",
            Number="0"
        );
        (Last=Number)
    ).

/*Checks whether S2 is a part of S1, S1 can be comma list or range*/
ipv6_contains(S1,S2):-
    reduce_ipv6(S1,Str1),
    reduce_ipv6(S2,Str2),
    ((Str1=Str2;string_concat(Str1,"/",Temp),string_concat(Temp,_,Str2);string_concat(Str2,"/",Temp2),string_concat(Temp2,_,Str1));alphabet_commalist_contains(Str1,Str2);ipv6_range_contains(Str1,Str2)).

/*Compares ip of the form x.x.x.x.x.x.x.y-x.x.x.x.x.x.x.z*/
ipv6_range_contains(Range,IP):-
    split_string(Range,"-","",[E1|[E2]]),
    ipv6_lastnum(E1,N1),
    ipv6_lastnum(E2,N2),
    ipv6_lastnum(IP,N3),
    string_concat(TEMP,N1,E1),
    string_concat(TEMP,N3,IP),
    number_string(Num1,N1),
    number_string(Num2,N2),
    number_string(Num3,N3),
    Num1=<Num3,
    Num3=<Num2.

/*-------------------------------------------Utility Function end---------------------------------------------*/

/*-------------------------------------Rule Checking functions for Reject-----------------------------------------*/


reject_adapter(X):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    [H1|[H2|T]]=L,
    H1="reject",
    H2="adapter",
    T=[Y],
    (Y=X; alphabet_commalist_contains(Y,X); alphabet_rangelist_contains(Y,X)).


reject_ethernet(Vid,ProtoID):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    length(L,Length),
    (
        (
           Length is 4,
           [H1|[H2|[H3|T]]]=L,
           H1="reject",
           H2="ether",
           (
              (
                 H3="proto",
                 T=[Y],
                 (Y=ProtoID;alphabet_commalist_contains(Y,ProtoID))
               );
              (
                 H3="vid",
                 T=[Y],
                 (Y=Vid;number_rangelist_contains(Y,Vid))
              )
           )
        );
        (
            Length is 6,
            [H1|[H2|[H3|[H4|[H5|T]]]]]=L,
            H1="reject",
            H2="ether",
            H3="vid",
            H5="proto",
            T=[Y],
            (Y=ProtoID;H4=Vid;alphabet_commalist_contains(Y,ProtoID);number_rangelist_contains(H4,Vid))

    )).


reject_icmp(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["reject"|["icmp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


reject_icmpv6(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["reject"|["icmpv6"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


reject_tcp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["reject"|["tcp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


reject_udp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["reject"|["udp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


reject_ip(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["reject"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ip"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ip_contains(H3,SrcAddr);ip_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ip"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ip_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ip_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ip"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ip"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr);H9=ProtoType)
        )
    ).


reject_ipv6(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["reject"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ipv6"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ipv6_contains(H3,SrcAddr);ipv6_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ipv6"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ipv6_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ipv6_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ipv6"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ipv6"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr);H9=ProtoType)
        )
    ).
/*-----------------------------Rule Checking Function for Reject End------------------------------*/



/*-----------------------------Rule Checking Function For Accept End *------------------------------*/


accept_adapter(X):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    [H1|[H2|T]]=L,
    H1="accept",
    H2="adapter",
    T=[Y],
    (Y=X; alphabet_commalist_contains(Y,X); alphabet_rangelist_contains(Y,X)).


accept_ethernet(Vid,ProtoID):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    length(L,Length),
    (
        (
           Length is 4,
           [H1|[H2|[H3|T]]]=L,
           H1="accept",
           H2="ether",
           (
              (
                 H3="proto",
                 T=[Y],
                 (Y=ProtoID;alphabet_commalist_contains(Y,ProtoID))
               );
              (
                 H3="vid",
                 T=[Y],
                 (Y=Vid;number_rangelist_contains(Y,Vid))
              )
           )
        );
        (
            Length is 6,
            [H1|[H2|[H3|[H4|[H5|T]]]]]=L,
            H1="accept",
            H2="ether",
            H3="vid",
            H5="proto",
            T=[Y],
            (Y=ProtoID;H4=Vid;alphabet_commalist_contains(Y,ProtoID);number_rangelist_contains(H4,Vid))

    )).


accept_icmp(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["accept"|["icmp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


accept_icmpv6(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["accept"|["icmpv6"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


accept_tcp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["accept"|["tcp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


accept_udp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["accept"|["udp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


accept_ip(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["accept"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ip"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ip_contains(H3,SrcAddr);ip_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ip"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ip_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ip_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ip"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ip"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr);H9=ProtoType)
        )
    ).


accept_ipv6(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["accept"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ipv6"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ipv6_contains(H3,SrcAddr);ipv6_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ipv6"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ipv6_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ipv6_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ipv6"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ipv6"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr);H9=ProtoType)
        )
    ).

/*----------------------------------Rule Checking Funtion For Accept End-----------------------------*/



/*-----------------------------------Rule Checking Function For Drop Start-----------------------------*/



drop_adapter(X):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    [H1|[H2|T]]=L,
    H1="drop",
    H2="adapter",
    T=[Y],
    (Y=X; alphabet_commalist_contains(Y,X); alphabet_rangelist_contains(Y,X)).


drop_ethernet(Vid,ProtoID):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    length(L,Length),
    (
        (
           Length is 4,
           [H1|[H2|[H3|T]]]=L,
           H1="drop",
           H2="ether",
           (
              (
                 H3="proto",
                 T=[Y],
                 (Y=ProtoID;alphabet_commalist_contains(Y,ProtoID))
               );
              (
                 H3="vid",
                 T=[Y],
                 (Y=Vid;number_rangelist_contains(Y,Vid))
              )
           )
        );
        (
            Length is 6,
            [H1|[H2|[H3|[H4|[H5|T]]]]]=L,
            H1="drop",
            H2="ether",
            H3="vid",
            H5="proto",
            T=[Y],
            (Y=ProtoID;H4=Vid;alphabet_commalist_contains(Y,ProtoID);number_rangelist_contains(H4,Vid))

    )).


drop_icmp(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["drop"|["icmp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


drop_icmpv6(Type,Code):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["drop"|["icmpv6"|T]]=L,
    length(L,Length),
    (
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="type",
            H4=Type

         );
        (
            Length is 4,
            [H3|[H4]]=T,
            H3="code",
            H4=Code
        );
        (
            Length is 6,
            [H3|[H4|[H5|[H6]]]]=T,
            H3="type",
            H5="code",
            (H4=Type;H6=Code)
        )
     ).


drop_tcp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["drop"|["tcp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


drop_udp(SrcPort,DstPort):-
    add_rule(Rule),
    split_string(Rule," "," ",L),
    ["drop"|["udp"|T]]=L,
    length(L,Length),
    (
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="src",
            H4="port",
            T2=[Y],
            (Y=SrcPort;number_rangelist_contains(Y,SrcPort);alphabet_commalist_contains(Y,SrcPort);number_not_rangelist_contains(Y,SrcPort))

         );
        (
            Length is 5,
            [H3|[H4|T2]]=T,
            H3="dst",
            H4="port",
            T2=[Y],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort))

        );
        (
            Length is 8,
            [H3|[H4|[H5|[H6|[H7|[H8]]]]]]=T,
            H3="dst",
            H4="port",
            H6="src",
            H7="port",
            H5=[Y],
            H8=[Z],
            (Y=DstPort;number_rangelist_contains(Y,DstPort);alphabet_commalist_contains(Y,DstPort);number_not_rangelist_contains(Y,DstPort);
            Z=SrcPort;number_rangelist_contains(Z,SrcPort);alphabet_commalist_contains(Z,SrcPort);number_not_rangelist_contains(Z,SrcPort))
        )
     ).


drop_ip(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["drop"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ip"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ip_contains(H3,SrcAddr);ip_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ip"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ip_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ip_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ip"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ip"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ip_contains(H4,SrcAddr);ip_contains(H7,DstAddr);H9=ProtoType)
        )
    ).


drop_ipv6(SrcAddr,DstAddr,ProtoType):-
    add_rule(Rule),
    split_string(Rule," ","",L),
    ["drop"|T]=L,
    length(L,Length),
    (
        (
            Length is 4,
            ["ipv6"|[H2|[H3]]]=T,
            (
            (
               H2="addr",
               (ipv6_contains(H3,SrcAddr);ipv6_contains(H3,DstAddr))
             );
            (
               H2="proto",
               H3=ProtoType
             ))
         );
        (
            Length is 5,
            ["ipv6"|[H2|[H3|[H4]]]]=T,
            (
               (
                  H2="src",
                  H3="addr",
                  ipv6_contains(H4,SrcAddr)
                );
               (
                  H2="dst",
                  H3="addr",
                  ipv6_contains(H4,DstAddr)
                )
             )
        );
        (
            Length is 8,
            ["ipv6"|[H2|[H3|[H4|[H5|[H6|[H7]]]]]]]=T,
            H2="src",
            H3="addr",
            H5="dst",
            H6="addr",
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr))
        );
        (
            Length is 9,
            ["ipv6"|["src"|["addr"|[H4|["dst"|["addr"|[H7|["proto"|[H9]]]]]]]]]=T,
            (ipv6_contains(H4,SrcAddr);ipv6_contains(H7,DstAddr);H9=ProtoType)
        )
    ).

/*----------------------------------Rule Checking Functiion For Drop ends-------------------------------------*/



/*----------------------------------------Engine of the Program-----------------------------------*/


check_packet(AdapterName,VID,ProtoID,IPtype,SrcIP,DstIP,ProtoType,Dginfo1,Dginfo2):-
    (
	(   (
            reject_adapter(AdapterName);
            reject_ethernet(VID,ProtoID);
            (
		(
                    IPtype="ip",
                    reject_ip(SrcIP,DstIP,ProtoType)
                 );
		(
                    IPtype="ipv6",
                    reject_ipv6(SrcIP,DstIP,ProtoType)
                )
            );
            (
		(
			ProtoType="tcp",
                    reject_tcp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="udp",
			reject_udp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmp",
			reject_icmp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmpv6",
                    reject_icmpv6(Dginfo1,Dginfo2)
                )
            )
        ),write("Packet Rejected"))
	;
	((
		drop_adapter(AdapterName);
            drop_ethernet(VID,ProtoID);
            (
		(
			IPtype="ip",
                    drop_ip(SrcIP,DstIP,ProtoType)
                );
		(
			IPtype="ipv6",
                    drop_ipv6(SrcIP,DstIP,ProtoType)
                )
            );
            (
		(
			ProtoType="tcp",
                    drop_tcp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="udp",
			drop_udp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmp",
			drop_icmp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmpv6",
                    drop_icmpv6(Dginfo1,Dginfo2)
                )
            )
        ),write("Packet Dropped"))
	;
        (   (
		accept_adapter(AdapterName);
            accept_ethernet(VID,ProtoID);
            (
		(
			IPtype="ip",
                    accept_ip(SrcIP,DstIP,ProtoType)
                );
		(
			IPtype="ipv6",
                    accept_ipv6(SrcIP,DstIP,ProtoType)
                )
            );
           (
		(
			ProtoType="tcp",
                    accept_tcp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="udp",
			accept_udp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmp",
			accept_icmp(Dginfo1,Dginfo2)
                );
		(
			ProtoType="icmpv6",
                    accept_icmpv6(Dginfo1,Dginfo2)
                )
            )
        ),write("Packet Accepted"))
        ;
        (defaultRejected,write("No rules apply.Rejected."));
        (defaultDropped,write("No rules apply.Dropped"));
        (defaultAccepted,write("No rules apply.Accepted"))
).
















