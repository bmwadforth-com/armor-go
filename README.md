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
   armor "github.com/bmwadforth-com/armor-go/src"
   "github.com/bmwadforth-com/armor-go/src/util"
   "github.com/bmwadforth-com/armor-go/src/util/jwt"
   jwtCommon "github.com/bmwadforth-com/armor-go/src/util/jwt/common"
   "os"
)

type Configuration struct {
   DbConnString string `json:"db_conn_string"`
   Keys         struct {
      ApiKey            string `json:"api_key"`
      JwePrivateKeyPath string `json:"jwe_private_key_path"`
      JwePublicKeyPath  string `json:"jwe_public_key_path"`
   } `json:"keys"`
}

func main() {
   myConfig := Configuration{}

   _ = armor.InitArmor(false, myConfig, "/path/to/config/config.json")
   defer armor.CleanupLogger(util.Logger)

   key, _ := os.ReadFile(myConfig.Keys.JwePublicKeyPath)
   claims := jwtCommon.NewClaimSet()
   err := claims.Add(string(jwtCommon.Audience), "developers")
   if err != nil {
      util.LogError("error occurred adding claim: %v", err)
   }

   token, err := jwt.New(jwtCommon.AlgorithmSuite{
      AlgorithmType:     jwtCommon.RSA_OAEP,
      AuthAlgorithmType: jwtCommon.A256GCM,
   }, claims, key)
   if err != nil {
      util.LogError("error occurred adding claim: %v", err)
   }

   encodedBytes, err := jwt.Encode(token)
   if err != nil {
      util.LogError("error occurred encoding token: %v", err)
   }

   util.Log("JWE Token: %s", string(encodedBytes))
}

```
