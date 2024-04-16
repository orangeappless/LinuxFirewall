#!/bin/bash

# User-specified host so that the script runs the proper setup depening on machine
OPTION=$1

# Firewall network parameters
INTERNAL_INTERFACE="eth0"
INTERNAL_SUBNET="192.168.10.0/24"
INTERNAL_ADDRESS="192.168.10.1"

EXTERNAL_INTERFACE="wlan0"
EXTERNAL_SUBNET="192.168.1.0/24"
EXTERNAL_ADDRESS="192.168.1.80"

# Internal host network parameters
INTERNAL_HOST_INTERNAL_INTERFACE="enp0s20f0u4"
INTERNAL_HOST_INTERNAL_ADDRESS="192.168.10.2"
INTERNAL_HOST_EXTERNAL_INTERFACE="wlp2s0"

# Firewall rules parameters
ALLOWED_TCP="22,53,67,68,80,443,5000" # ssh,dns,dhcp,dhcp,http,https,demo-test-port
ALLOWED_UDP="53,67,68" # dns,dhcp,dhcp
ALLOWED_ICMP="0,3,8" # echo-reply,destination-unreachable,echo-request


# Hosts setup
configure_fw_host() {
    # Configure internal interface
    ifconfig $INTERNAL_INTERFACE $INTERNAL_ADDRESS up

    echo "1" >/proc/sys/net/ipv4/ip_forward

    # Configure routes
    route add -net $EXTERNAL_SUBNET gw $EXTERNAL_ADDRESS
    route add -net $INTERNAL_SUBNET gw $INTERNAL_ADDRESS

    # Configure masquerade
    iptables -A POSTROUTING -t nat -s $INTERNAL_SUBNET -o $EXTERNAL_INTERFACE -j MASQUERADE
}

configure_internal_host() {
    ifconfig $INTERNAL_HOST_EXTERNAL_INTERFACE down
    ifconfig $INTERNAL_HOST_INTERNAL_INTERFACE $INTERNAL_HOST_INTERNAL_ADDRESS up

    route add default gw $INTERNAL_ADDRESS
}


# Reset all iptables settings
reset_rules() {
    # Reset to default policies
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT

    iptables -t nat -P PREROUTING ACCEPT
    iptables -t nat -P POSTROUTING ACCEPT
    iptables -t nat -P OUTPUT ACCEPT

    iptables -t mangle -P PREROUTING ACCEPT
    iptables -t mangle -P POSTROUTING ACCEPT
    iptables -t mangle -P INPUT ACCEPT
    iptables -t mangle -P OUTPUT ACCEPT
    iptables -t mangle -P FORWARD ACCEPT

    # Flush rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F

    # Erase chains
    iptables -X
    iptables -t nat -X
    iptables -t mangle -X
}

# Firewall rules
default_drop() {
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP
}

create_chains() {
    # Create inbound/outbound chains for protocols
    iptables -N tcpin
    iptables -N tcpout

    iptables -N udpin
    iptables -N udpout

    iptables -N icmpin
    iptables -N icmpout

    iptables -A INPUT -j tcpin
    iptables -A INPUT -j udpin
    iptables -A INPUT -j icmpin

    iptables -A OUTPUT -j tcpout
    iptables -A OUTPUT -j udpout
    iptables -A OUTPUT -j icmpout

    iptables -A FORWARD -j tcpin
    iptables -A FORWARD -j udpin
    iptables -A FORWARD -j icmpin
    
    iptables -A FORWARD -j tcpout
    iptables -A FORWARD -j udpout
    iptables -A FORWARD -j icmpout 
}

drop_match_internal_ip() {
    # Drops packets from source IP matching internal host's IP
    iptables -A tcpin -i $EXTERNAL_INTERFACE -p tcp -s $INTERNAL_HOST_INTERNAL_ADDRESS -j DROP
    iptables -A udpin -i $EXTERNAL_INTERFACE -p udp -s $INTERNAL_HOST_INTERNAL_ADDRESS -j DROP
}

drop_tcp_sin_fyn() {
    # Drops TCP packets that have both SYN and FIN flags set
    iptables -A tcpin -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 
    iptables -A tcpout -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP 
}

drop_telnet() {
    # Drops all Telnet packets (both directions; inbound and outbound)
    # TCP port 23
    iptables -A tcpin -p tcp --dport 23 -j DROP
    iptables -A tcpin -p tcp --sport 23 -j DROP

    iptables -A tcpout -p tcp --dport 23 -j DROP
    iptables -A tcpout -p tcp --sport 23 -j DROP
}

drop_inbound_port80() {
    # iptables -A tcpin -i $EXTERNAL_INTERFACE -p tcp --dport 80 --sport 0:1023 -j DROP
    iptables -A tcpin -i $EXTERNAL_INTERFACE -p tcp --sport 0:1023 -j DROP
}

drop_port0() {
    # Drop all packets to/from port 0
    # TCP packets
    iptables -A tcpin -p tcp --dport 0 -j DROP
    iptables -A tcpin -p tcp --sport 0 -j DROP

    iptables -A tcpout -p tcp --dport 0 -j DROP
    iptables -A tcpout -p tcp --sport 0 -j DROP

    # UDP packets
    iptables -A udpin -p udp --dport 0 -j DROP
    iptables -A udpin -p udp --sport 0 -j DROP

    iptables -A udpout -p udp --dport 0 -j DROP
    iptables -A udpout -p udp --sport 0 -j DROP    
}

permit_ssh() {
    # Allows all SSH packets (both directions; inbound and outpound)
    # TCP port 22
    iptables -A tcpin -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpin -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    iptables -A tcpout -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpout -p tcp --sport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT    
}

permit_www() {
    # Allows all www connections (both directions; inbound and outpound)
    # TCP port 80 (http)
    iptables -A tcpin -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpin -p tcp --sport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    iptables -A tcpout -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpout -p tcp --sport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # TCP port 443 (https)
    iptables -A tcpin -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpin -p tcp --sport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    iptables -A tcpout -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpout -p tcp --sport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT   
}

forward_ssh() {
    # External to internal
    iptables -t nat -A PREROUTING -i $EXTERNAL_INTERFACE -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j DNAT --to-destination $INTERNAL_HOST_INTERNAL_ADDRESS
    iptables -A FORWARD -i $EXTERNAL_INTERFACE -o $INTERNAL_INTERFACE -p tcp --dport 22 -j ACCEPT

    # Internal to external
    iptables -t nat -A PREROUTING -i $INTERNAL_INTERFACE -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j DNAT --to-destination 192.168.1.64
    iptables -A FORWARD -i $INTERNAL_INTERFACE -o $EXTERNAL_INTERFACE -p tcp --dport 22 -j ACCEPT
}

accept_allowed() {
    # TCP ports
    iptables -A tcpin -p tcp -m multiport --dports $ALLOWED_TCP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpin -p tcp -m multiport --sports $ALLOWED_TCP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    iptables -A tcpout -p tcp -m multiport --dports $ALLOWED_TCP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A tcpout -p tcp -m multiport --sports $ALLOWED_TCP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # UDP ports
    iptables -A udpin -p udp -m multiport --dports $ALLOWED_UDP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A udpin -p udp -m multiport --sports $ALLOWED_UDP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    iptables -A udpout -p udp -m multiport --dports $ALLOWED_UDP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    iptables -A udpout -p udp -m multiport --sports $ALLOWED_UDP -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

    # ICMP ports
    iptables -A icmpin -p icmp -m conntrack --ctstate NEW,ESTABLISHED-j ACCEPT

    iptables -A icmpout -p icmp -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
}

set_mindelay_maxthroughput() {
    iptables -A PREROUTING -t mangle -p tcp --sport ssh -j TOS --set-tos Minimize-Delay
    iptables -A PREROUTING -t mangle -p tcp --sport ftp -j TOS --set-tos Minimize-Delay

    iptables -A PREROUTING -t mangle -p tcp --sport ftp-data -j TOS --set-tos Maximize-Throughput
}


if [[ $(id -u) -ne 0 ]]; then
    echo "Elevated privileges required"
    exit
elif [ $# = 1 ]; then
    if [ "$OPTION" = "firewall" ]; then
        echo "Setting up firewall network settings..."
        configure_fw_host
        echo "Firewall network settings set!"

    elif [ "$OPTION" = "internal" ]; then
        echo "internal host setup will begin..."

    elif [ "$OPTION" = "reset" ]; then
        echo "Resetting firewall rules..."
        reset_rules
        echo "Firewall rules reset!"

    elif [ "$OPTION" = "rules" ]; then
        echo "Adding firewall rules..."

        create_chains

        # Set default policies to drop
        default_drop

        # Do not accept any packets with a source address from the outside matching your internal network
        drop_match_internal_ip

        # Drop all TCP packets with the SYN and FIN bit set
        drop_tcp_sin_fyn

        # Do not allow Telnet packets at all.
        drop_telnet

        # Drop inbound traffic to port 80 (htttp) from source ports less than 1024
        drop_inbound_port80

        # Drop all incoming packets from reserved port 0 as well as outbound traffic to port 0
        drop_port0

        # Permit inbound/outbound SSH
        permit_ssh

        # Permit inbound/outbound www packets
        permit_www

        # Forward ssh to internal host
        forward_ssh

        # Accept all allowed ports
        accept_allowed

        # For FTP and SSH services, set control connections to "Minimum Delay" and FTP data to "Maximum Throughput".
        set_mindelay_maxthroughput

        echo "Firewall rules added!"

    else
        echo "Incorrect usage: ./setup.sh [ firewall | internal | rules | reset ]"
        exit
    fi
else
    echo "Please specify one (1) argument"
    exit
fi
