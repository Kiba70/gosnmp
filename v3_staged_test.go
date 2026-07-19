// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"bytes"
	"errors"
	"io"
	"log"
	"testing"
)

func TestV3PacketDecoderSeparatesStages(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	receiver := stagedSecurityParameters(99, 999, SHA, NoPriv)
	params := newTestGoSNMPv3(AuthNoPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	header := decoder.Header()
	if header.EngineBoots != 1 || header.EngineTime != 2 || header.UserName != "probe" {
		t.Fatalf("wire header = %+v", header)
	}
	if err := decoder.Authenticate(receiver); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := decoder.Decrypt(); !errors.Is(err, ErrInvalidV3DecodeStage) {
		t.Fatalf("Decrypt without timeliness error = %v", err)
	}
	if err := decoder.ValidateTimeliness(func(header V3PacketHeader) error {
		if header.EngineBoots != 1 || header.EngineTime != 2 {
			t.Fatalf("timeliness header = %+v", header)
		}
		return nil
	}); err != nil {
		t.Fatalf("ValidateTimeliness: %v", err)
	}
	if err := decoder.Decrypt(); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	packet, err := decoder.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if packet.PDUType != InformRequest {
		t.Fatalf("PDU type = %s", packet.PDUType)
	}
	security := packet.SecurityParameters.(*UsmSecurityParameters)
	if security.AuthenticationPassphrase != "" || security.PrivacyPassphrase != "" || security.SecretKey != nil || security.PrivacyKey != nil {
		t.Fatal("decoded packet exposes credentials")
	}
}

func TestV3PacketDecoderRejectsForeignEngineID(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
	receiver.AuthoritativeEngineID = string([]byte{0x80, 0x00, 0x1f, 0x80, 0x05, 9, 9, 9, 9, 9, 9, 9})
	params := newTestGoSNMPv3(AuthNoPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); !errors.Is(err, ErrUnknownEngineID) {
		t.Fatalf("Authenticate error = %v", err)
	}
}

func TestV3PacketDecoderRejectsWrongUsername(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
	receiver.UserName = "other"
	params := newTestGoSNMPv3(AuthNoPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); !errors.Is(err, ErrUnknownUsername) {
		t.Fatalf("Authenticate error = %v", err)
	}
}

func TestV3PacketDecoderReportsWrongDigest(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	raw[len(raw)-1] ^= 0xff
	receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
	params := newTestGoSNMPv3(AuthNoPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); !errors.Is(err, ErrWrongDigest) {
		t.Fatalf("Authenticate error = %v", err)
	}
}

func TestV3PacketDecoderAuthPriv(t *testing.T) {
	raw := marshalStagedInform(t, AuthPriv, SHA, AES)
	receiver := stagedSecurityParameters(1, 2, SHA, AES)
	params := newTestGoSNMPv3(AuthPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := decoder.ValidateTimeliness(func(V3PacketHeader) error { return nil }); err != nil {
		t.Fatalf("ValidateTimeliness: %v", err)
	}
	if err := decoder.Decrypt(); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	packet, err := decoder.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if packet.PDUType != InformRequest || len(packet.Variables) != 1 {
		t.Fatalf("decoded packet = %+v", packet)
	}
}

func TestV3PacketDecoderAuthProtocols(t *testing.T) {
	protocols := []SnmpV3AuthProtocol{MD5, SHA, SHA224, SHA256, SHA384, SHA512}
	for _, protocol := range protocols {
		t.Run(protocol.String(), func(t *testing.T) {
			raw := marshalStagedInform(t, AuthNoPriv, protocol, NoPriv)
			receiver := stagedSecurityParameters(1, 2, protocol, NoPriv)
			params := newTestGoSNMPv3(AuthNoPriv, receiver)
			decoder, err := params.NewV3PacketDecoder(raw)
			if err != nil {
				t.Fatalf("NewV3PacketDecoder: %v", err)
			}
			if err := decoder.Authenticate(receiver); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
		})
	}
}

func TestV3PacketDecoderPrivacyProtocols(t *testing.T) {
	protocols := []SnmpV3PrivProtocol{DES, AES, AES192, AES256, AES192C, AES256C}
	for _, protocol := range protocols {
		t.Run(protocol.String(), func(t *testing.T) {
			raw := marshalStagedInform(t, AuthPriv, SHA, protocol)
			receiver := stagedSecurityParameters(1, 2, SHA, protocol)
			params := newTestGoSNMPv3(AuthPriv, receiver)
			decoder, err := params.NewV3PacketDecoder(raw)
			if err != nil {
				t.Fatalf("NewV3PacketDecoder: %v", err)
			}
			if err := decoder.Authenticate(receiver); err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if err := decoder.ValidateTimeliness(func(V3PacketHeader) error { return nil }); err != nil {
				t.Fatalf("ValidateTimeliness: %v", err)
			}
			if err := decoder.Decrypt(); err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if _, err := decoder.DecodePayload(); err != nil {
				t.Fatalf("DecodePayload: %v", err)
			}
		})
	}
}

func TestV3PacketDecoderRejectsInvalidCredentials(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	params := newTestGoSNMPv3(AuthNoPriv, nil)

	t.Run("empty passphrase", func(t *testing.T) {
		receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
		receiver.AuthenticationPassphrase = ""
		decoder, err := params.NewV3PacketDecoder(raw)
		if err != nil {
			t.Fatalf("NewV3PacketDecoder: %v", err)
		}
		if err := decoder.Authenticate(receiver); err == nil {
			t.Fatal("empty authentication passphrase accepted")
		}
	})

	t.Run("short passphrase", func(t *testing.T) {
		receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
		receiver.AuthenticationPassphrase = "short"
		decoder, err := params.NewV3PacketDecoder(raw)
		if err != nil {
			t.Fatalf("NewV3PacketDecoder: %v", err)
		}
		if err := decoder.Authenticate(receiver); err == nil {
			t.Fatal("short authentication passphrase accepted")
		}
	})

	t.Run("short localized auth key", func(t *testing.T) {
		receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
		receiver.AuthenticationPassphrase = ""
		receiver.SecretKey = []byte{1}
		decoder, err := params.NewV3PacketDecoder(raw)
		if err != nil {
			t.Fatalf("NewV3PacketDecoder: %v", err)
		}
		if err := decoder.Authenticate(receiver); err == nil {
			t.Fatal("short localized authentication key accepted")
		}
	})

	t.Run("short localized privacy key", func(t *testing.T) {
		privateRaw := marshalStagedInform(t, AuthPriv, SHA, DES)
		receiver := stagedSecurityParameters(1, 2, SHA, DES)
		receiver.PrivacyPassphrase = ""
		receiver.PrivacyKey = []byte{1}
		decoder, err := params.NewV3PacketDecoder(privateRaw)
		if err != nil {
			t.Fatalf("NewV3PacketDecoder: %v", err)
		}
		if err := decoder.Authenticate(receiver); err == nil {
			t.Fatal("short localized privacy key accepted")
		}
	})
}

func TestV3PacketDecoderNoAuthWithoutCredentials(t *testing.T) {
	security := &UsmSecurityParameters{Logger: stagedDiscardLogger()}
	packet := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           NoAuthNoPriv | Reportable,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: security,
		PDUType:            GetRequest,
		MsgID:              303,
		RequestID:          404,
		MsgMaxSize:         65535,
		Logger:             stagedDiscardLogger(),
	}
	raw, err := packet.MarshalMsg()
	if err != nil {
		t.Fatalf("MarshalMsg: %v", err)
	}
	params := newTestGoSNMPv3(NoAuthNoPriv, nil)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(nil); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := decoder.ValidateTimeliness(func(V3PacketHeader) error { return nil }); err != nil {
		t.Fatalf("ValidateTimeliness: %v", err)
	}
	if err := decoder.Decrypt(); err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	decoded, err := decoder.DecodePayload()
	if err != nil {
		t.Fatalf("DecodePayload: %v", err)
	}
	if decoded.PDUType != GetRequest {
		t.Fatalf("PDU type = %s", decoded.PDUType)
	}
}

func TestV3PacketDecoderNoAuthUserRequiresCredentials(t *testing.T) {
	raw := marshalStagedInform(t, NoAuthNoPriv, NoAuth, NoPriv)
	receiver := stagedSecurityParameters(1, 2, NoAuth, NoPriv)
	params := newTestGoSNMPv3(NoAuthNoPriv, receiver)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(nil); err == nil {
		t.Fatal("ordinary noAuth packet accepted without credentials")
	}
	decoder, err = params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); err != nil {
		t.Fatalf("Authenticate with noAuth credentials: %v", err)
	}
}

func TestV3PacketDecoderTimelinessFailureBlocksDecrypt(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	receiver := stagedSecurityParameters(1, 2, SHA, NoPriv)
	params := newTestGoSNMPv3(AuthNoPriv, receiver)
	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	if err := decoder.Authenticate(receiver); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if err := decoder.ValidateTimeliness(nil); err == nil {
		t.Fatal("nil timeliness validator accepted")
	}
	want := errors.New("stale packet")
	if err := decoder.ValidateTimeliness(func(V3PacketHeader) error { return want }); !errors.Is(err, want) {
		t.Fatalf("ValidateTimeliness error = %v", err)
	}
	if err := decoder.Decrypt(); !errors.Is(err, ErrInvalidV3DecodeStage) {
		t.Fatalf("Decrypt after rejected timeliness error = %v", err)
	}
}

func TestV3PacketDecoderRejectsInvalidSecurityFlags(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	flags := bytes.Index(raw, []byte{byte(OctetString), 1, byte(AuthNoPriv | Reportable)})
	if flags < 0 {
		t.Fatal("msgFlags not found")
	}
	raw[flags+2] = 0x06
	params := newTestGoSNMPv3(AuthNoPriv, nil)
	if _, err := params.NewV3PacketDecoder(raw); err == nil {
		t.Fatal("invalid priv-without-auth flags accepted")
	}
}

func TestV3PacketDecoderDoesNotMutateInputOrHeader(t *testing.T) {
	raw := marshalStagedInform(t, AuthNoPriv, SHA, NoPriv)
	want := append([]byte(nil), raw...)
	params := newTestGoSNMPv3(AuthNoPriv, nil)

	decoder, err := params.NewV3PacketDecoder(raw)
	if err != nil {
		t.Fatalf("NewV3PacketDecoder: %v", err)
	}
	header := decoder.Header()
	header.AuthParameters[0] ^= 0xff
	if bytes.Equal(header.AuthParameters, decoder.Header().AuthParameters) {
		t.Fatal("Header returned shared authentication parameters")
	}
	if !bytes.Equal(raw, want) {
		t.Fatal("constructor mutated input packet")
	}
}

func TestV3PacketDecoderTruncatedPacketsDoNotPanic(t *testing.T) {
	raw := marshalStagedInform(t, AuthPriv, SHA, AES)
	params := newTestGoSNMPv3(AuthPriv, nil)
	for size := range len(raw) {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("packet length %d panicked: %v", size, recovered)
				}
			}()
			_, _ = params.NewV3PacketDecoder(raw[:size])
		}()
	}
}

func TestV3PacketDecoderRejectsOversizedBERLength(t *testing.T) {
	params := newTestGoSNMPv3(AuthPriv, nil)
	raw := []byte{byte(Sequence), 0x84, 0xff, 0xff, 0xff, 0xff}
	if _, err := params.NewV3PacketDecoder(raw); err == nil {
		t.Fatal("oversized BER length accepted")
	}
}

func TestHMACReturnsPasswordError(t *testing.T) {
	if _, err := hMAC(SHA.HashType(), "", "", "engine"); err == nil {
		t.Fatal("empty password error was suppressed")
	}
}

func FuzzV3PacketDecoder(f *testing.F) {
	f.Add(marshalStagedInform(f, AuthNoPriv, SHA, NoPriv))
	f.Add([]byte{byte(Sequence), 0x84, 0xff, 0xff, 0xff, 0xff})
	params := newTestGoSNMPv3(AuthPriv, nil)
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoder, err := params.NewV3PacketDecoder(raw)
		if err == nil {
			_ = decoder.Header()
		}
	})
}

func marshalStagedInform(tb testing.TB, flags SnmpV3MsgFlags, auth SnmpV3AuthProtocol, privacy SnmpV3PrivProtocol) []byte {
	tb.Helper()
	security := stagedSecurityParameters(1, 2, auth, privacy)
	if err := security.InitSecurityKeys(); err != nil {
		tb.Fatalf("InitSecurityKeys: %v", err)
	}
	packet := &SnmpPacket{
		Version:            Version3,
		MsgFlags:           flags | Reportable,
		SecurityModel:      UserSecurityModel,
		SecurityParameters: security,
		ContextEngineID:    security.AuthoritativeEngineID,
		PDUType:            InformRequest,
		MsgID:              101,
		RequestID:          202,
		MsgMaxSize:         65535,
		Logger:             stagedDiscardLogger(),
		Variables: []SnmpPDU{{
			Name:  ".1.3.6.1.2.1.1.3.0",
			Type:  TimeTicks,
			Value: uint32(1),
		}},
	}
	if err := security.InitPacket(packet); err != nil {
		tb.Fatalf("InitPacket: %v", err)
	}
	raw, err := packet.MarshalMsg()
	if err != nil {
		tb.Fatalf("MarshalMsg: %v", err)
	}
	return raw
}

func stagedSecurityParameters(boots, engineTime uint32, auth SnmpV3AuthProtocol, privacy SnmpV3PrivProtocol) *UsmSecurityParameters {
	return &UsmSecurityParameters{
		AuthoritativeEngineID:    string([]byte{0x80, 0x00, 0x1f, 0x80, 0x05, 1, 2, 3, 4, 5, 6, 7}),
		AuthoritativeEngineBoots: boots,
		AuthoritativeEngineTime:  engineTime,
		UserName:                 "probe",
		AuthenticationProtocol:   auth,
		AuthenticationPassphrase: "eid017-auth-passphrase",
		PrivacyProtocol:          privacy,
		PrivacyPassphrase:        "eid017-priv-passphrase",
		Logger:                   stagedDiscardLogger(),
	}
}

func stagedDiscardLogger() Logger {
	return NewLogger(log.New(io.Discard, "", 0))
}
