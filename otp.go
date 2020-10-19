// MIT License
//
// Copyright (c) 2020 zxdev
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

// Interval timeframe; default 30-second
var Interval = time.Second * 30

// Entropy bytes for Secret generation; default 20
var Entropy = 20

// number digits emitted format
var zPad = "%06d" // zero pad
var zN = 1000000  // n zeros

// Sizer configures the package level otp digit size; default 6
func Sizer(n int) {
	zPad = fmt.Sprintf("%%0%dd", n)
	zN = int(math.Pow(10, float64(n)))
}

// Secret generator; default 20 Entropy bytes
// eg. AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25
func Secret() string {
	b := make([]byte, Entropy)
	rand.Read(b[:])
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// HOTPToken generation requires a secret and a timeframe interval
func HOTPToken(secret string, interval int64) string {

	// convert secret to base32 Encoding; letters A–Z and digits 0–9
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(interval))

	// sign the value using HMAC-SHA1 algorithm
	hash := hmac.New(sha1.New, key)
	hash.Write(bs)
	h := hash.Sum(nil)

	// use the last nibble (a half-byte) to choose the start index since this value
	// is at most 0xF (decimal 15), and there are 20 bytes of SHA1; we need 4 bytes
	// to get a 32 bit chunk from hash starting n index; per RFC 4226 we ignore the
	// significant bits via int and do modulo with 100000000 to generate 8 digit otp
	n := (h[19] & 0xf)
	header := binary.BigEndian.Uint32(h[n : n+4])
	return fmt.Sprintf(zPad, (int(header)&0x7fffffff)%zN)

}

// Token is a HOTPToken with an Interval seed
func Token(secret string) string {
	return HOTPToken(secret,
		time.Now().Round(Interval).Unix())
}

// Tokens is a HOTPToken with a bracketed [last|now|next] Interval seed range
func Tokens(secret string) [3]string {
	return [3]string{
		HOTPToken(secret, time.Now().Add(-Interval).Round(Interval).Unix()),
		HOTPToken(secret, time.Now().Round(Interval).Unix()),
		HOTPToken(secret, time.Now().Add(Interval).Round(Interval).Unix()),
	}
}
