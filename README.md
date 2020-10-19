# One Time Pass

This one time token generator is based off [RFC 4226](https://tools.ietf.org/html/rfc4226) and generates tokens based on a shared secret and the time interval.

## Variables

* Interval - default 30-seconds
* Entropy - number of bytes for Secret; default 20

## Functions

* Sizer - specify the number of digits to emit; default 6
* Secret - random secret generator; eg. AW6TJVTYMAYJXLWFW2WWJ6D3Q5B2AY25
* HOTPToken - generation requires a secret and an interval timeframe
* Token - is a HOTPToken with current Interval seed
* Tokens - is a HOTPToken with a bracketed last|now|next current Interval seed range

```golang

func main() {

  secret := "secretsecretsecret"

  fmt.Println(otp.Token(secret))  // 397657
  fmt.Println(otp.Tokens(secret)) // [755604 397657 140422]

  otp.Sizer(10)

  fmt.Println(otp.Token(secret))  // 1545628642
  fmt.Println(otp.Tokens(secret)) // [0511092633 1545628642 1383583942]
  
}

```