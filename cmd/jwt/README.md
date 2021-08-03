# `jwt` command-line tool

This is a simple tool to sign, verify and show JSON Web Tokens from
the command line.

The following will create and sign a token, then verify it and output the original claims:

- To sign a claim object

```bash
echo {\"foo\":\"bar\"} | ./jwt -key ../../test/sample_key -alg RS256 -sign -
```

- To verify a token

```bash
JWT=$(echo {\"foo\":\"bar\"} | ./jwt -key ../../test/sample_key -alg RS256 -sign -)
echo ${JWT} | ./jwt -key ../../test/sample_key.pub -alg RS256 -verify -
```

- To simply display a token

```bash
JWT=$(echo {\"foo\":\"bar\"} | ./jwt -key ../../test/sample_key -alg RS256 -sign -)
echo $JWT | ./jwt -show -
```

## Installation

Simply: `go install github.com/dgrijalva/cmd/jwt`

Or you can download the code, compile it, and put the result wherever you like.
