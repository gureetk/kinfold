// SPDX-License-Identifier: AGPL-3.0-or-later

// Package push builds what a server sends a device by any route but the device's own
// connection (PROTOCOL.md §14.2): a Push signed with the server key, padded to 2,560 bytes
// and sealed with HPKE to the device's current encryption key, 2,616 bytes in all. It also
// signs requests to the iOS relay (§14.4) and wraps pushes for Apple (API.md §12).
package push

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/gureetk/kinfold/server/internal/identity"
	"github.com/gureetk/kinfold/server/internal/kcrypto"
	"github.com/gureetk/kinfold/server/internal/wire"
)

// Push types.
const (
	Wake    = 1
	Records = 2
	Silence = 3
)

// Relay delivery types (§14.4).
const (
	Alert      = 1
	Background = 2
	Location   = 3
)

const (
	MaxBody   = 2483
	PlainLen  = 2560
	SealedLen = 2616
)

// ErrBody is a body that doesn't fit its type or the size limit.
var ErrBody = errors.New("push body doesn't fit its type")

// Build returns the Push for a device: version 0, the type, sent_at and body, signed with
// the server key over recipient_device_id ‖ everything before the signature.
func Build(server ed25519.PrivateKey, recipient []byte, ptype uint8, sentAt uint64, body []byte) ([]byte, error) {
	switch {
	case len(body) > MaxBody,
		ptype == Wake && len(body) != 0,
		ptype == Records && len(body) == 0,
		ptype == Silence && len(body) != 40,
		ptype < Wake || ptype > Silence:
		return nil, ErrBody
	}
	tbs := wire.Concat([]byte{identity.Version, ptype}, wire.U64(sentAt), wire.Vec16(body))
	return append(tbs, kcrypto.Sign(server, "push-sig", recipient, tbs)...), nil
}

// Info is the HPKE info of a push: H("push", device_id ‖ key_id).
func Info(deviceID, keyID []byte) []byte { return kcrypto.H("push", deviceID, keyID) }

// Seal pads a Push to 2,560 bytes and seals it to the device's encryption key with a
// fresh ephemeral key: key_id[8] ‖ enc[32] ‖ ct, 2,616 bytes.
func Seal(p, deviceID, dek []byte) ([]byte, error) {
	if len(p) >= PlainLen {
		return nil, ErrBody
	}
	kid := identity.KeyID(dek)
	enc, ct, err := kcrypto.Seal(dek, Info(deviceID, kid), wire.PadTo(p, PlainLen))
	if err != nil {
		return nil, err
	}
	return wire.Concat(kid, enc, ct), nil
}

// Record is one delivery record: u64 received_at ‖ envelope (API.md §7).
func Record(receivedAt uint64, envelope []byte) []byte {
	return wire.Concat(wire.U64(receivedAt), envelope)
}

// RecordsBody is the body of a `records` push: each record as u32 length ‖ record.
func RecordsBody(records [][]byte) []byte {
	var out []byte
	for _, r := range records {
		out = wire.AppendFrame(out, r)
	}
	return out
}

// SilenceBody is the body of a `silence` push.
func SilenceBody(circleID, watchedDevice []byte, lastSeenAt uint64) []byte {
	return wire.Concat(circleID, watchedDevice, wire.U64(lastSeenAt))
}

// RelaySig signs a request to the iOS relay:
// Sign(server key, "relay-push", capability ‖ sealed ‖ u64(sent_at) ‖ u8(delivery)).
func RelaySig(server ed25519.PrivateKey, capability, sealed []byte, sentAt uint64, delivery uint8) []byte {
	return kcrypto.Sign(server, "relay-push", capability, sealed, wire.U64(sentAt), []byte{delivery})
}

// AppleNote is a sealed push as an Apple notification (API.md §12), the same whether the
// relay sends it or a server with its own Apple key: the push type, what the bundle ID takes
// as a suffix to make the topic, the priority, when Apple stops trying (UNIX seconds) and
// the JSON payload.
type AppleNote struct {
	PushType    string
	TopicSuffix string
	Priority    int
	Expiration  int64
	Payload     []byte
}

// Fallback names the app's string for an alert its notification extension can't open.
const Fallback = "push_fallback"

// ForApple wraps a sealed push for Apple. An alert or a background push is kept for an hour,
// as Web Push is; a location push for 10 minutes, past which the phone would drop it
// (PROTOCOL.md §14.2).
func ForApple(delivery uint8, sealed []byte, sentAt uint64) (AppleNote, error) {
	k := wire.EncodeB64u(sealed)
	at := int64(sentAt / 1000)
	var n AppleNote
	var aps map[string]any
	switch delivery {
	case Alert:
		n = AppleNote{PushType: "alert", Priority: 10, Expiration: at + 3600}
		aps = map[string]any{"alert": map[string]string{"loc-key": Fallback}, "mutable-content": 1, "sound": "default"}
	case Background:
		n = AppleNote{PushType: "background", Priority: 5, Expiration: at + 3600}
		aps = map[string]any{"content-available": 1}
	case Location:
		n = AppleNote{PushType: "location", TopicSuffix: ".location-query", Priority: 10, Expiration: at + 600}
		aps = map[string]any{}
	default:
		return n, errors.New("push: no such delivery type")
	}
	payload, err := json.Marshal(map[string]any{"aps": aps, "kinfold": k})
	n.Payload = payload
	return n, err
}
