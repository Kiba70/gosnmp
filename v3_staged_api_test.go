// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp_test

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestV3PacketDecoderPublicAPI(t *testing.T) {
	params := &gosnmp.GoSNMP{}
	var constructor func([]byte) (*gosnmp.V3PacketDecoder, error)
	constructor = params.NewV3PacketDecoder
	if constructor == nil {
		t.Fatal("NewV3PacketDecoder is nil")
	}

	var decoder *gosnmp.V3PacketDecoder
	_ = decoder.Header
	_ = decoder.Authenticate
	_ = decoder.ValidateTimeliness
	_ = decoder.Decrypt
	_ = decoder.DecodePayload
	_ = gosnmp.UsmStatsNotInTimeWindowsOID
	_ = gosnmp.UsmStatsUnknownEngineIDsOID
}
