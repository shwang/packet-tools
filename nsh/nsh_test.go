package nsh

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/assert"
)

func TestIsomorphicSerialization(t *testing.T) {
	nsh := NSH{
		Version: 0,
		Length: 6,
		Protocol: NSHProtocolIPv4,
		MDType: MDTypeOne,

		ServicePathIdentifier: 777,
		ServiceIndex: 7,
		Context: [4]NSHContextHeader{1,2,3,4},
	}

	buf := gopacket.NewSerializeBuffer()
	nsh.SerializeTo(buf, gopacket.SerializeOptions{})

	var nshDecoded NSH
	err := nshDecoded.DecodeFromBytes(buf.Bytes(), gopacket.NilDecodeFeedback)
	assert.NoError(t, err)

	buf2 := gopacket.NewSerializeBuffer()
	nshDecoded.SerializeTo(buf2, gopacket.SerializeOptions{})

	assert.Equal(t, nsh, nshDecoded)
	assert.Equal(t, buf.Bytes(), buf2.Bytes())
}
