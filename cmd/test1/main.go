package main

import (
	"fmt"
	//wg "github.com/binrick/go-check-wireguard"
	wgt "github.com/binrick/go-check-wireguard/types"
	"github.com/k0kubun/pp"
)

func main() {
	pp.Println(&wgt.EncodedKeys{})

	fmt.Println("vim-go")
}
