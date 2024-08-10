# armor-go

## Publishing

Merging into master will cause the code in master to be released. The version of the release will depend on your commit
message. Your commit messages will follow the conventions
defined [here](https://www.conventionalcommits.org/en/v1.0.0/).

1. PR is merged into master
2. If your last commit to the base branch merging into master followed the commit conventions defined earlier a PR will
   be created automatically to create a new release
3. Once the above PR is merged a new release will be created for you to use in your own Go projects.

## Quick Start

Here's an example on how you can use armor-go.

```go
package main

import (
	"fmt"
	armor "github.com/bmwadforth-com/armor-go/src/util"
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
