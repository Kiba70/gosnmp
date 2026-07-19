// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

package gosnmp_test

import (
	"testing"

	"github.com/gosnmp/gosnmp"
)

func TestV3PacketDecoderPublicAPI(_ *testing.T) {
	params := &gosnmp.GoSNMP{}
	_ = params.NewV3PacketDecoder

	var decoder *gosnmp.V3PacketDecoder
	_ = decoder.Header
	_ = decoder.Authenticate
	_ = decoder.ValidateTimeliness
	_ = decoder.Decrypt
	_ = decoder.DecodePayload
	_ = gosnmp.UsmStatsNotInTimeWindowsOID
	_ = gosnmp.UsmStatsUnknownEngineIDsOID
}
