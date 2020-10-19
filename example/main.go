package main

import (
	"fmt"

	"github.com/zxdev/otp"
)

func main() {

	secret := otp.Secret()
	fmt.Println(secret)

	fmt.Println(otp.Token(secret))  // 397657
	fmt.Println(otp.Tokens(secret)) // [755604 397657 140422]

	otp.Sizer(10)

	fmt.Println(otp.Token(secret))  // 1545628642
	fmt.Println(otp.Tokens(secret)) // [0511092633 1545628642 1383583942]

}
