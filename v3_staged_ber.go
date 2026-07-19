// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp

import (
	"errors"
	"fmt"
)

var errInvalidStagedBER = errors.New("invalid SNMPv3 BER")

func parseV3PacketHeader(raw []byte) (V3PacketHeader, error) {
	var result V3PacketHeader
	root := stagedBERCursor{data: raw}
	message, err := root.readExpected(byte(Sequence))
	if err != nil || !root.done() {
		return result, fmt.Errorf("SNMP message: %w", errInvalidStagedBER)
	}

	body := stagedBERCursor{data: message.value, base: message.valueOffset}
	version, err := body.readUint32()
	if err != nil || version != uint32(Version3) {
		return result, fmt.Errorf("SNMP version: %w", errInvalidStagedBER)
	}
	headerTLV, err := body.readExpected(byte(Sequence))
	if err != nil {
		return result, fmt.Errorf("msgGlobalData: %w", err)
	}
	header := stagedBERCursor{data: headerTLV.value, base: headerTLV.valueOffset}
	if result.MsgID, err = header.readUint32(); err != nil {
		return result, fmt.Errorf("msgID: %w", err)
	}
	if result.MsgID > 2147483647 {
		return result, fmt.Errorf("msgID range: %w", errInvalidStagedBER)
	}
	if result.MsgMaxSize, err = header.readUint32(); err != nil {
		return result, fmt.Errorf("msgMaxSize: %w", err)
	}
	if result.MsgMaxSize < 484 || result.MsgMaxSize > 2147483647 {
		return result, fmt.Errorf("msgMaxSize range: %w", errInvalidStagedBER)
	}
	flags, err := header.readOctets()
	if err != nil || len(flags.value) != 1 {
		return result, fmt.Errorf("msgFlags: %w", errInvalidStagedBER)
	}
	result.MsgFlags = SnmpV3MsgFlags(flags.value[0])
	if result.MsgFlags&^(AuthPriv|Reportable) != 0 || result.MsgFlags&AuthPriv == 0x02 {
		return result, fmt.Errorf("msgFlags 0x%02x: %w", result.MsgFlags, errInvalidStagedBER)
	}
	securityModel, err := header.readUint32()
	if err != nil || securityModel != uint32(UserSecurityModel) || !header.done() {
		return result, fmt.Errorf("msgSecurityModel: %w", errInvalidStagedBER)
	}
	result.SecurityModel = UserSecurityModel

	securityContainer, err := body.readOctets()
	if err != nil {
		return result, fmt.Errorf("msgSecurityParameters: %w", err)
	}
	securityOuter := stagedBERCursor{data: securityContainer.value, base: securityContainer.valueOffset}
	securityTLV, err := securityOuter.readExpected(byte(Sequence))
	if err != nil || !securityOuter.done() {
		return result, fmt.Errorf("USM parameters: %w", errInvalidStagedBER)
	}
	security := stagedBERCursor{data: securityTLV.value, base: securityTLV.valueOffset}
	engineID, err := security.readOctets()
	if err != nil {
		return result, fmt.Errorf("msgAuthoritativeEngineID: %w", err)
	}
	result.EngineID = string(engineID.value)
	if len(result.EngineID) != 0 && (len(result.EngineID) < 5 || len(result.EngineID) > 32) {
		return result, fmt.Errorf("msgAuthoritativeEngineID length: %w", errInvalidStagedBER)
	}
	if result.EngineBoots, err = security.readUint32(); err != nil {
		return result, fmt.Errorf("msgAuthoritativeEngineBoots: %w", err)
	}
	if result.EngineTime, err = security.readUint32(); err != nil {
		return result, fmt.Errorf("msgAuthoritativeEngineTime: %w", err)
	}
	if result.EngineBoots > 2147483647 || result.EngineTime > 2147483647 {
		return result, fmt.Errorf("engine boots/time range: %w", errInvalidStagedBER)
	}
	userName, err := security.readOctets()
	if err != nil || len(userName.value) > 32 {
		return result, fmt.Errorf("msgUserName: %w", errInvalidStagedBER)
	}
	result.UserName = string(userName.value)
	authParameters, err := security.readOctets()
	if err != nil {
		return result, fmt.Errorf("msgAuthenticationParameters: %w", err)
	}
	result.AuthParameters = append([]byte(nil), authParameters.value...)
	privacyParameters, err := security.readOctets()
	if err != nil || !security.done() {
		return result, fmt.Errorf("msgPrivacyParameters: %w", errInvalidStagedBER)
	}
	result.PrivacyParameters = append([]byte(nil), privacyParameters.value...)

	scopedPDU, err := body.readTLV()
	if err != nil || !body.done() {
		return result, fmt.Errorf("scopedPDUData: %w", errInvalidStagedBER)
	}
	result.Encrypted = scopedPDU.tag == byte(OctetString)
	if result.Encrypted {
		if result.MsgFlags&AuthPriv != AuthPriv || len(result.PrivacyParameters) != 8 {
			return result, fmt.Errorf("encrypted scoped PDU security level: %w", errInvalidStagedBER)
		}
	} else {
		if scopedPDU.tag != byte(Sequence) || result.MsgFlags&AuthPriv == AuthPriv || len(result.PrivacyParameters) != 0 {
			return result, fmt.Errorf("plaintext scoped PDU security level: %w", errInvalidStagedBER)
		}
	}
	if result.MsgFlags&AuthNoPriv == 0 && len(result.AuthParameters) != 0 {
		return result, fmt.Errorf("noAuth packet has authentication parameters: %w", errInvalidStagedBER)
	}
	if result.MsgFlags&AuthNoPriv != 0 && len(result.AuthParameters) == 0 {
		return result, fmt.Errorf("authenticated packet has empty authentication parameters: %w", errInvalidStagedBER)
	}
	return result, nil
}

type stagedBERTLV struct {
	tag         byte
	value       []byte
	valueOffset int
}

type stagedBERCursor struct {
	data []byte
	base int
	pos  int
}

func (c *stagedBERCursor) done() bool {
	return c.pos == len(c.data)
}

func (c *stagedBERCursor) readExpected(expected byte) (stagedBERTLV, error) {
	value, err := c.readTLV()
	if err != nil {
		return stagedBERTLV{}, err
	}
	if value.tag != expected {
		return stagedBERTLV{}, fmt.Errorf("expected tag 0x%02x, got 0x%02x: %w", expected, value.tag, errInvalidStagedBER)
	}
	return value, nil
}

func (c *stagedBERCursor) readOctets() (stagedBERTLV, error) {
	return c.readExpected(byte(OctetString))
}

func (c *stagedBERCursor) readUint32() (uint32, error) {
	value, err := c.readExpected(byte(Integer))
	if err != nil {
		return 0, err
	}
	return stagedParseUint32(value.value)
}

func (c *stagedBERCursor) readTLV() (stagedBERTLV, error) {
	if c.pos >= len(c.data) {
		return stagedBERTLV{}, errInvalidStagedBER
	}
	tag := c.data[c.pos]
	c.pos++
	length, consumed, err := stagedDecodeLength(c.data[c.pos:])
	if err != nil {
		return stagedBERTLV{}, err
	}
	c.pos += consumed
	if length > uint64(len(c.data)-c.pos) { //nolint:gosec // Остаток буфера неотрицателен.
		return stagedBERTLV{}, errInvalidStagedBER
	}
	valueLength := int(length) //nolint:gosec // Граница проверена относительно доступного int-sized буфера.
	valueOffset := c.base + c.pos
	value := c.data[c.pos : c.pos+valueLength]
	c.pos += valueLength
	return stagedBERTLV{tag: tag, value: value, valueOffset: valueOffset}, nil
}

func stagedParseUint32(raw []byte) (uint32, error) {
	if len(raw) == 0 || len(raw) > 5 || raw[0]&0x80 != 0 {
		return 0, errInvalidStagedBER
	}
	if len(raw) == 5 {
		if raw[0] != 0 {
			return 0, errInvalidStagedBER
		}
		raw = raw[1:]
	}
	var result uint32
	for _, value := range raw {
		result = result<<8 | uint32(value)
	}
	return result, nil
}

func stagedDecodeLength(raw []byte) (uint64, int, error) {
	if len(raw) == 0 {
		return 0, 0, errInvalidStagedBER
	}
	if raw[0]&0x80 == 0 {
		return uint64(raw[0]), 1, nil
	}
	count := int(raw[0] & 0x7f)
	if count == 0 || count > 4 || len(raw) < count+1 || raw[1] == 0 {
		return 0, 0, errInvalidStagedBER
	}
	var length uint64
	for _, value := range raw[1 : count+1] {
		length = length<<8 | uint64(value)
	}
	if length < 128 {
		return 0, 0, errInvalidStagedBER
	}
	return length, count + 1, nil
}
