# Galaxy

## Quick Start

Here's an example on how you can use Galaxy.

```go
package main

import (
	"fmt"
	galaxyutil "github.com/bmwadforth/galaxy/src/util"
)

func main() {
	galaxyutil.InitLogger()

	data := struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}{Name: "John", Age: 30}

	result, err := galaxyutil.SerializeJson(data)
	if err != nil {
		// Handle error
	}

	fmt.Println(result)
}

```