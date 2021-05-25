# Crystal Lang NTLM Auth

[![CI](https://github.com/spider-gazelle/ntlm/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/ntlm/actions/workflows/ci.yml)

Communicate with servers that implement NTLM auth.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     ntlm:
       github: spider-gazelle/ntlm
   ```

2. Run `shards install`


## Usage

### Authenticate a HTTP request

```crystal

require "http/client"
require "ntlm"

route = "/terrible/soap/api"
username = "username"
password = "password"

# NOTE:: domain is not always required, this can sometimes be left `nil`
domain = "DOMAIN"

client = HTTP::Client.new "corporate.service"
response = client.get route

if response.status_code == 401 && response.headers["WWW-Authenticate"]?
  supported = response.headers.get("WWW-Authenticate")
  raise "doesn't support NTLM auth: #{supported}" unless supported.includes?("NTLM")

  # Negotiate NTLM
  response = client.get route, HTTP::Headers{"Authorization" => NTLM.negotiate_http(domain)}

  # Extract the challenge
  raise "unexpected response #{response.status_code}" unless response.status_code == 401 && response.headers["WWW-Authenticate"]?
  challenge = response.headers["WWW-Authenticate"]

  # Authenticate the client
  response = client.get route, HTTP::Headers{"Authorization" => NTLM.authenticate_http(challenge, username, password)}
end

response

```
