package nsh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	LayerTypeNSH = gopacket.RegisterLayerType(777,
		gopacket.LayerTypeMetadata{
			Name: "NSH",
			Decoder: gopacket.DecodeFunc(decodeNSH),
		})
)

type NSH struct {
	layers.BaseLayer
	Version uint8
	OperationsBit bool
	CriticalBit bool
	Length uint8
	MDType NshMDType
	Protocol NSHProtocol

	ServicePathIdentifier uint32
	ServiceIndex uint8
	Context [4]NSHContextHeader
}

type NshMDType uint8
const (
	MDTypeOne NshMDType = 0x1
	MDTypeTwo NshMDType = 0x2
)

type NSHProtocol uint8
const (
	NSHProtocolIPv4 NSHProtocol = 0x1
	NSHProtocolIPv6 NSHProtocol = 0x2
	NSHProtocolEthernet NSHProtocol = 0x3
	NSHProtocolNSH NSHProtocol = 0x4
	NSHProtocolMPLS NSHProtocol = 0x5
	NSHProtocolExperiment1 NSHProtocol = 0xFE
	NSHProtocolExperiment2 NSHProtocol = 0xFF
)

type NSHContextHeader uint32

// TODO: support Variable length context headers in addition to fixed length

const EthernetTypeNSH layers.EthernetType = 0x894F

// XXX: Before merging upstream, move this init() into layers.enums.init()
func init() {
	layers.EthernetTypeMetadata[EthernetTypeNSH] = layers.EnumMetadata{
		DecodeWith: gopacket.DecodeFunc(decodeNSH),
		Name:"NSH",
		LayerType: LayerTypeNSH,
	}
}

func (nsh *NSH) LayerType() gopacket.LayerType { return LayerTypeNSH }

func (nsh *NSH) SerializeTo(b gopacket.SerializeBuffer,
	opts gopacket.SerializeOptions) error {

	if nsh.MDType != MDTypeOne {
		return fmt.Errorf("unsupported MDType %d. " +
			"Only MDTypeOne is supported", nsh.MDType)
	}

	if nsh.Version != 0 {
		return errors.New("Only nsh.Version = 0 is supported")
	}

	// TODO: allow other lengths
	if nsh.Length != 6 {
		return errors.New("Only nsh.Length = 6 is supported")
	}

	if nsh.Length > (1 << 6) - 1 {
		return errors.New("nsh.Length exceeds maximum")
	}

	bytes, err := b.PrependBytes(int(nsh.Length) * 4)
	if err != nil {
		return err
	}
	bytes[0] = nsh.Version << 6
	if nsh.OperationsBit {
		bytes[0] += 2
	}
	if nsh.CriticalBit {
		bytes[0] += 1
	}

	bytes[1] = nsh.Length
	bytes[2] = byte(nsh.MDType)
	bytes[3] = byte(nsh.Protocol)
	binary.BigEndian.PutUint32(bytes[4:],
		nsh.ServicePathIdentifier << 8 | uint32(nsh.ServiceIndex))
	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(bytes[8+4*i:], uint32(nsh.Context[i]))
	}

	return nil
}

func (nsh *NSH) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	nsh.Version = uint8(data[0]) >> 6
	nsh.OperationsBit = (uint8(data[0]) >> 5) & 1 == 1
	nsh.CriticalBit = (uint8(data[0]) >> 4) & 1 == 1
	nsh.Length = uint8(data[1]) & 0x1F
	nsh.MDType = NshMDType(uint8(data[2]))
	nsh.Protocol = NSHProtocol(uint(data[3]))
	nsh.ServicePathIdentifier = binary.BigEndian.Uint32(data[4:8]) >> 8
	nsh.ServiceIndex = data[7]

	for i := 0; i < 4; i++ {
		nsh.Context[i] = NSHContextHeader(binary.BigEndian.Uint32(data[8+4*i:]))
	}

	nsh.BaseLayer = layers.BaseLayer{data[nsh.Length*4:], data[nsh.Length*4:]}
	return nil
}

func (nsh *NSH) CanDecode() gopacket.LayerClass {
	return LayerTypeNSH
}

func (nsh *NSH) NextLayerType() gopacket.LayerType {
	switch nsh.Protocol {
	case NSHProtocolIPv4:
		return layers.LayerTypeIPv4
	default:
		// TODO: Allow other layers
		return layers.LayerTypeIPv4
	}
}

func decodeNSH(data []byte, p gopacket.PacketBuilder) error {
	nsh := &NSH{}
	err := nsh.DecodeFromBytes(data, p)
	p.AddLayer(nsh)
	if err != nil {
		return err
	}
	return p.NextDecoder(nsh.NextLayerType())
}
