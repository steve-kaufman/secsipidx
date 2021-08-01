package secsipid_test

import (
	"fmt"
	"testing"

	"github.com/asipto/secsipidx/secsipid"
)

type CertVerifyTest struct {
	certVerify int

	shouldVerifyWithTime           bool
	shouldVerifyWithSystemCA       bool
	shouldVerifyWithCustomCA       bool
	shouldVerifyWithIntermediateCA bool
	shouldVerifyWithCLRFile        bool
}

var certVerifyTests = []CertVerifyTest{
	{
		certVerify:           0b00001,
		shouldVerifyWithTime: true,
	},
	{
		certVerify:               0b00010,
		shouldVerifyWithSystemCA: true,
	},
	{
		certVerify:               0b00100,
		shouldVerifyWithCustomCA: true,
	},
	{
		certVerify:                     0b01000,
		shouldVerifyWithIntermediateCA: true,
	},
	{
		certVerify:              0b10000,
		shouldVerifyWithCLRFile: true,
	},
	{
		certVerify: 0b00000,
	},
	{
		certVerify:                     0b11111,
		shouldVerifyWithTime:           true,
		shouldVerifyWithSystemCA:       true,
		shouldVerifyWithCustomCA:       true,
		shouldVerifyWithIntermediateCA: true,
		shouldVerifyWithCLRFile:        true,
	},
}

func TestCertVerify(t *testing.T) {
	for _, tc := range certVerifyTests {
		t.Run(fmt.Sprint(tc.certVerify), func(t *testing.T) {
			testCertVerify(t, tc)
		})
	}
}

func testCertVerify(t *testing.T, tc CertVerifyTest) {
	options := secsipid.SJWTLibOptions{
		CertVerify: tc.certVerify,
	}

	if options.ShouldVerifyWithTime() != tc.shouldVerifyWithTime {
		t.Fatalf("Expected ShouldVerifyWithTime() to be: %v, got: %v",
			tc.shouldVerifyWithTime,
			options.ShouldVerifyWithTime())
	}
	if options.ShouldVerifyWithSystemCA() != tc.shouldVerifyWithSystemCA {
		t.Fatalf("Expected ShouldVerifyWithSystemCA to be: %v, got: %v",
			tc.shouldVerifyWithSystemCA,
			options.ShouldVerifyWithSystemCA())
	}
	if options.ShouldVerifyWithCustomCA() != tc.shouldVerifyWithCustomCA {
		t.Fatalf("Expected ShouldVerifyWithCustomCA to be: %v, got: %v",
			tc.shouldVerifyWithCustomCA,
			options.ShouldVerifyWithCustomCA())
	}
	if options.ShouldVerifyWithIntermediateCA() != tc.shouldVerifyWithIntermediateCA {
		t.Fatalf("Expected ShouldVerifyWithIntermediateCA to be: %v, got: %v",
			tc.shouldVerifyWithIntermediateCA,
			options.ShouldVerifyWithIntermediateCA())
	}
	if options.ShouldVerifyWithCLRFile() != tc.shouldVerifyWithCLRFile {
		t.Fatalf("Expected ShouldVerifyWithCLRFile to be: %v, got: %v",
			tc.shouldVerifyWithCLRFile,
			options.ShouldVerifyWithCLRFile())
	}
}
