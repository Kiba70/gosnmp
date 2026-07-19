// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
)

var ErrInvalidV3DecodeStage = errors.New("invalid SNMPv3 decode stage")

const (
	UsmStatsNotInTimeWindowsOID = usmStatsNotInTimeWindows
	UsmStatsUnknownEngineIDsOID = usmStatsUnknownEngineIDs
)

// V3PacketHeader содержит только wire metadata и не раскрывает credentials или локализованные ключи.
type V3PacketHeader struct {
	MsgID             uint32
	MsgMaxSize        uint32
	MsgFlags          SnmpV3MsgFlags
	SecurityModel     SnmpV3SecurityModel
	EngineID          string
	EngineBoots       uint32
	EngineTime        uint32
	UserName          string
	AuthParameters    []byte
	PrivacyParameters []byte
	Encrypted         bool
}

type v3DecodeStage uint8

const (
	v3StageParsed v3DecodeStage = iota + 1
	v3StageAuthenticated
	v3StageTimelinessAccepted
	v3StageDecrypted
	v3StageDecoded
)

// V3PacketDecoder разделяет parse, authentication, timeliness и decrypt.
// Один decoder обрабатывает один packet и не предназначен для конкурентного использования.
type V3PacketDecoder struct {
	goSNMP *GoSNMP
	raw    []byte
	header V3PacketHeader
	packet *SnmpPacket
	cursor int
	stage  v3DecodeStage
}

// NewV3PacketDecoder безопасно разбирает global header и USM metadata без credentials.
func (x *GoSNMP) NewV3PacketDecoder(raw []byte) (*V3PacketDecoder, error) {
	if x == nil {
		return nil, errors.New("GoSNMP is nil")
	}
	header, err := parseV3PacketHeader(raw)
	if err != nil {
		return nil, err
	}
	return &V3PacketDecoder{
		goSNMP: x,
		raw:    append([]byte(nil), raw...),
		header: header,
		stage:  v3StageParsed,
	}, nil
}

// Header возвращает независимую копию wire metadata.
func (d *V3PacketDecoder) Header() V3PacketHeader {
	if d == nil {
		return V3PacketHeader{}
	}
	result := d.header
	result.AuthParameters = append([]byte(nil), d.header.AuthParameters...)
	result.PrivacyParameters = append([]byte(nil), d.header.PrivacyParameters...)
	return result
}

// Authenticate проверяет выбранные credentials, EngineID, username и digest без decrypt.
// Для noAuth packet credentials могут быть nil.
func (d *V3PacketDecoder) Authenticate(credentials SnmpV3SecurityParameters) error {
	if err := d.requireStage(v3StageParsed); err != nil {
		return err
	}

	working := append([]byte(nil), d.raw...)
	result := new(SnmpPacket)
	discovery := d.header.MsgFlags&AuthPriv == NoAuthNoPriv && d.header.EngineID == "" && d.header.EngineBoots == 0 && d.header.EngineTime == 0 && d.header.UserName == ""
	if credentials == nil {
		if !discovery {
			return errors.New("USM credentials are required outside discovery")
		}
		result.SecurityParameters = &UsmSecurityParameters{Logger: d.goSNMP.Logger}
	} else {
		provided, ok := credentials.(*UsmSecurityParameters)
		if !ok || provided == nil {
			return errors.New("USM credentials have an invalid type")
		}
		usmCredentials := provided.Copy().(*UsmSecurityParameters)
		if err := usmCredentials.validate(d.header.MsgFlags); err != nil {
			return err
		}
		if usmCredentials.UserName != d.header.UserName {
			return ErrUnknownUsername
		}
		if usmCredentials.AuthoritativeEngineID != d.header.EngineID {
			return ErrUnknownEngineID
		}
		if d.header.MsgFlags&AuthNoPriv != 0 {
			if len(usmCredentials.SecretKey) == 0 && len(usmCredentials.AuthenticationPassphrase) < 8 {
				return errors.New("USM authentication passphrase must contain at least 8 octets")
			}
			expectedAuthSize, err := usmAuthParameterSize(usmCredentials.AuthenticationProtocol)
			if err != nil {
				return err
			}
			if len(d.header.AuthParameters) != expectedAuthSize {
				return fmt.Errorf("unexpected authentication parameter length %d, want %d", len(d.header.AuthParameters), expectedAuthSize)
			}
		}
		if d.header.MsgFlags&AuthPriv == AuthPriv && len(usmCredentials.PrivacyKey) == 0 && len(usmCredentials.PrivacyPassphrase) < 8 {
			return errors.New("USM privacy passphrase must contain at least 8 octets")
		}
		if err := usmCredentials.InitSecurityKeys(); err != nil {
			return fmt.Errorf("error initializing SNMPv3 security keys: %w", err)
		}
		if err := validateUSMKeyLengths(usmCredentials, d.header.MsgFlags); err != nil {
			return err
		}
		result.SecurityParameters = usmCredentials
	}

	cursor, err := d.goSNMP.unmarshalHeader(working, result)
	if err != nil {
		return fmt.Errorf("error parsing validated SNMPv3 header: %w", err)
	}
	if result.Version != Version3 || result.SecurityModel != UserSecurityModel {
		return errors.New("validated SNMPv3 header changed during decode")
	}
	if d.header.MsgFlags&AuthNoPriv != 0 {
		authentic, err := result.SecurityParameters.isAuthentic(working, result)
		if err != nil {
			return err
		}
		if !authentic {
			return ErrWrongDigest
		}
	}

	d.raw = working
	d.packet = result
	d.cursor = cursor
	d.stage = v3StageAuthenticated
	return nil
}

// ValidateTimeliness делает timeliness обязательной стадией до decrypt.
// Callback должен проверить authoritative EngineID, boots/time и локальный epoch.
func (d *V3PacketDecoder) ValidateTimeliness(validate func(V3PacketHeader) error) error {
	if err := d.requireStage(v3StageAuthenticated); err != nil {
		return err
	}
	if validate == nil {
		return errors.New("timeliness validator is nil")
	}
	if err := validate(d.Header()); err != nil {
		return err
	}
	d.stage = v3StageTimelinessAccepted
	return nil
}

// Decrypt расшифровывает scoped PDU только после успешной timeliness-проверки.
func (d *V3PacketDecoder) Decrypt() error {
	if err := d.requireStage(v3StageTimelinessAccepted); err != nil {
		return err
	}
	working := append([]byte(nil), d.raw...)
	packetBytes, cursor, err := d.goSNMP.decryptPacket(working, d.cursor, d.packet)
	if err != nil {
		return err
	}
	d.raw = packetBytes
	d.cursor = cursor
	d.stage = v3StageDecrypted
	return nil
}

// DecodePayload разбирает scoped PDU после authentication, timeliness и decrypt.
func (d *V3PacketDecoder) DecodePayload() (*SnmpPacket, error) {
	if err := d.requireStage(v3StageDecrypted); err != nil {
		return nil, err
	}
	if err := d.goSNMP.unmarshalPayload(d.raw, d.cursor, d.packet); err != nil {
		return nil, err
	}
	d.stage = v3StageDecoded
	return sanitizedPacketCopy(d.packet), nil
}

func (d *V3PacketDecoder) requireStage(expected v3DecodeStage) error {
	if d == nil {
		return fmt.Errorf("decoder is nil: %w", ErrInvalidV3DecodeStage)
	}
	if d.stage != expected {
		return fmt.Errorf("expected stage %d, got %d: %w", expected, d.stage, ErrInvalidV3DecodeStage)
	}
	return nil
}

func usmAuthParameterSize(protocol SnmpV3AuthProtocol) (int, error) {
	if int(protocol) >= len(macVarbinds) {
		return 0, ErrUnknownSecurityLevel
	}
	parameters := macVarbinds[protocol]
	if len(parameters) < 2 {
		return 0, ErrUnknownSecurityLevel
	}
	return len(parameters) - 2, nil
}

func validateUSMKeyLengths(credentials *UsmSecurityParameters, flags SnmpV3MsgFlags) error {
	if flags&AuthNoPriv != 0 {
		expected := map[SnmpV3AuthProtocol]int{
			MD5: 16, SHA: 20, SHA224: 28, SHA256: 32, SHA384: 48, SHA512: 64,
		}[credentials.AuthenticationProtocol]
		if expected == 0 || len(credentials.SecretKey) != expected {
			return fmt.Errorf("invalid localized authentication key length %d", len(credentials.SecretKey))
		}
	}
	if flags&AuthPriv == AuthPriv {
		if credentials.PrivacyProtocol == DES {
			if len(credentials.PrivacyKey) < 16 {
				return fmt.Errorf("invalid localized privacy key length %d", len(credentials.PrivacyKey))
			}
			return nil
		}
		expected := map[SnmpV3PrivProtocol]int{
			AES: 16, AES192: 24, AES256: 32, AES192C: 24, AES256C: 32,
		}[credentials.PrivacyProtocol]
		if expected == 0 || len(credentials.PrivacyKey) != expected {
			return fmt.Errorf("invalid localized privacy key length %d", len(credentials.PrivacyKey))
		}
	}
	return nil
}

func sanitizedPacketCopy(packet *SnmpPacket) *SnmpPacket {
	result := *packet
	result.Variables = append([]SnmpPDU(nil), packet.Variables...)
	if security, ok := packet.SecurityParameters.(*UsmSecurityParameters); ok {
		securityCopy := security.Copy().(*UsmSecurityParameters)
		securityCopy.AuthenticationPassphrase = ""
		securityCopy.PrivacyPassphrase = ""
		securityCopy.SecretKey = nil
		securityCopy.PrivacyKey = nil
		securityCopy.AuthenticationParameters = ""
		result.SecurityParameters = securityCopy
	}
	return &result
}
