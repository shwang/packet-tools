package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/sirspinach/packet-tools/nsh"
)

func main() {
	inHandle, err := pcap.OpenOffline("/udp-test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer inHandle.Close()

	outHandle, err := pcap.OpenLive("eth0", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer outHandle.Close()

	count := 0

	pktSrc := gopacket.NewPacketSource(inHandle, inHandle.LinkType())
	for pkt := range pktSrc.Packets() {
		modPkt, err := modifyPacket(pkt)
		fmt.Println("original")
		fmt.Println(pkt)
		fmt.Println()
		fmt.Println("modified")
		fmt.Println(modPkt)

		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println()
		outHandle.WritePacketData(modPkt.Data())

		count++
		if count >= 10 {
			break
		}
	}
}

// Return a tunneled GRE variant of the packet. The tunnel IP will be the same
// as the original IP. The ethernet address will remain unchanged.
func modifyPacket(pkt gopacket.Packet) (gopacket.Packet, error) {
	link, ok := pkt.LinkLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf("Link layer is not serialiable %q\n", link)
	}

	network, ok := pkt.NetworkLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf("Network layer is not serializable %q\n", network)
	}

	transport, ok := pkt.TransportLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf(
			"Transport layer is not serializable %q\n", transport)
	}

	application, ok := pkt.ApplicationLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf(
			"Application layer is not serializable %q\n", application)
	}

	ipExpectGRE := *(pkt.NetworkLayer().(*layers.IPv4)) // Create a copy of the original IP layer
	ipExpectGRE.Protocol = layers.IPProtocolGRE

	gre := &layers.GRE{Protocol: nsh.EthernetTypeNSH}
	nshLayer := nsh.NSH{
		Version: 0,
		Length: 6,
		Protocol: nsh.NSHProtocolIPv4,
		MDType: nsh.MDTypeOne,

		ServicePathIdentifier: 777,
		ServiceIndex: 7,
		Context: [4]nsh.NSHContextHeader{1,2,3,4},
	}

	decodableNetwork, ok := pkt.NetworkLayer().(gopacket.DecodingLayer)
	fmt.Println("gre next layer", gre.NextLayerType(), "\n", "network next layer", decodableNetwork.NextLayerType())

	buf := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums:true},
		transport,
		application)

	fullOpts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	network.SerializeTo(buf, fullOpts)
	nshLayer.SerializeTo(buf, fullOpts)
	gre.SerializeTo(buf, fullOpts)
	ipExpectGRE.SerializeTo(buf, fullOpts)
	link.SerializeTo(buf, fullOpts)

	return gopacket.NewPacket(buf.Bytes(),
		layers.LayerTypeEthernet, gopacket.Default), nil
}
