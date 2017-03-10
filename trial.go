package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	inHandle, err := pcap.OpenLive("en0", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer inHandle.Close()

	outHandle, err := pcap.OpenLive("en1", 1024, false, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	defer outHandle.Close()

	count := 0

	pktSrc := gopacket.NewPacketSource(inHandle, inHandle.LinkType())
	for pkt := range pktSrc.Packets() {
		modPkt, err := modifyPacket(pkt)
		fmt.Println(pkt)
		fmt.Println()
		fmt.Println(modPkt)
		if err != nil {
			fmt.Println(err)
			continue
		}
		fmt.Println()
		outHandle.WritePacketData(modPkt.Data())
		//outHandle.WritePacketData(pkt.Data())

		count++
		if count >= 10 {
			break
		}
	}
}

func listAll() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for _, dev := range devices {
		fmt.Println(dev)
	}
}

// Return a tunneled GRE(TODO: -NSH) variant of the packet. The tunnel IP will be the same
// as the original IP. The ethernet address will remain unchanged.
func modifyPacket(pkt gopacket.Packet) (gopacket.Packet, error) {
	fmt.Println("modPacket")
	link, ok := pkt.LinkLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf("Link layer is not serialiable %q\n", link)
	}

	network, ok := pkt.NetworkLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf("Network layer is not serializable %q\n", network)
	}

	transport, ok := pkt.NetworkLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf(
			"Transport layer is not serializable %q\n", transport)
	}

	application, ok := pkt.ApplicationLayer().(gopacket.SerializableLayer)
	if !ok {
		return nil, fmt.Errorf(
			"Application layer is not serializable %q\n", application)
	}

	//opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	opts := gopacket.SerializeOptions{}
	buf := gopacket.NewSerializeBuffer()

	gopacket.SerializeLayers(buf, opts,
		link,
		network,
		transport,
		application)

	// gre := layers.GRE{Protocol: layers.EthernetTypeIPv4}
	// greBytes := gre.LayerContents()

	// bufPre, err := buf.PrependBytes(len(greBytes))
	// if err != nil {
	// 	return nil, fmt.Errorf("Could not prepend greBytes: %s\n", bufPre)
	// }
	// if copy(bufPre, greBytes) != len(greBytes) {
	// 	return nil, fmt.Errorf("Unexpected copy length\n")
	// }

	// if err := network.SerializeTo(buf, opts); err != nil {
	// 	return nil, fmt.Errorf("Failed to serialize network layer: %s", err.Error())
	// }
	// if err := link.SerializeTo(buf, opts); err != nil {
	// 	return nil, fmt.Errorf("Failed to serialize link layer: %s", err.Error())
	// }

	return gopacket.NewPacket(buf.Bytes(),
		layers.LayerTypeEthernet, gopacket.Default), nil
}
