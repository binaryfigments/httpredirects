package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/binaryfigments/httpredirects"
)

func main() {
	url := strings.ToLower(os.Args[1])

	rd := httpredirects.Get(url, "1.1.1.1")

	json, err := json.MarshalIndent(rd, "", "  ")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\n", json)
}
