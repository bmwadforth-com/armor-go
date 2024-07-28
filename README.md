# armor-go

## Publishing
- Make your changes and create a PR to master
- Make sure the build and test pipeline passes
- If success, merge to master
- Checkout master and pull the latest
- Create a new tag and push tag
- Example: `git tag v1.0.0 && git push origin v1.0.0`
- The above command will publish a new version of the library to GCP artifactory based on the tag version

## Quick Start

Here's an example on how you can use armor-go.

```go
package main

import (
	"fmt"
	armor "github.com/bmwadforth/armor-go/src/util"
)

func main() {
	armor.InitLogger()

	data := struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}{Name: "John", Age: 30}

	result, err := armor.SerializeJson(data)
	if err != nil {
		// Handle error
	}

	fmt.Println(result)
}

```