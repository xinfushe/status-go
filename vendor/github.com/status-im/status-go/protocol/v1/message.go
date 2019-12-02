package protocol

import (
	"crypto/ecdsa"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"github.com/status-im/status-go/eth-node/crypto"
	"github.com/status-im/status-go/eth-node/types"
	"github.com/status-im/status-go/protocol/protobuf"
)

var (
	// ErrInvalidDecodedValue means that the decoded message is of wrong type.
	// This might mean that the status message serialization tag changed.
	ErrInvalidDecodedValue = errors.New("invalid decoded value type")
)

// TimestampInMsFromTime returns a TimestampInMs from a time.Time instance.
func TimestampInMsFromTime(t time.Time) uint64 {
	return uint64(t.UnixNano() / int64(time.Millisecond))
}

// Flags define various boolean properties of a message.
type Flags uint64

func (f *Flags) Set(val Flags)     { *f = *f | val }
func (f *Flags) Clear(val Flags)   { *f = *f &^ val }
func (f *Flags) Toggle(val Flags)  { *f = *f ^ val }
func (f Flags) Has(val Flags) bool { return f&val != 0 }

// A list of Message flags. By default, a message is unread.
const (
	MessageRead Flags = 1 << iota
)

// MessageID calculates the messageID from author's compressed public key
// and not encrypted but encoded payload.
func MessageID(author *ecdsa.PublicKey, data []byte) types.HexBytes {
	keyBytes := crypto.FromECDSAPub(author)
	return types.HexBytes(crypto.Keccak256(append(keyBytes, data...)))
}

// WrapMessageV1 wraps a payload into a protobuf message and signs it if an identity is provided
func WrapMessageV1(payload []byte, messageType protobuf.ApplicationMetadataMessage_MessageType, identity *ecdsa.PrivateKey) ([]byte, error) {
	var signature []byte
	if identity != nil {
		var err error
		signature, err = crypto.Sign(crypto.Keccak256(payload), identity)
		if err != nil {
			return nil, err
		}
	}

	message := &protobuf.ApplicationMetadataMessage{
		Signature:   signature,
		MessageType: messageType,
		Payload:     payload,
	}
	return proto.Marshal(message)
}
