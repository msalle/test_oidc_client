# Introduction
This is a very simple OpenID Connect client to debug OIDC flows. It can easily
be adapted to other OAuth2-based flows.

## Overview
It uses the endpoints obtained from the well-known/openid-configuration endpoint
to do a full OpenID-Connect authorization code flow.

- The flow is initiated by spawning a webbrowser to a (temporary) file to easily
  do a POST.
- It uses a localhost (python) webserver as redirect_uri. We're polling that
  server's log to see when the code is returned.
- The code is used by cURL to obtain the tokens and used for accessing the
  userinfo endpoint.
- During the flow, it will print out all the responses and tokens using json_pp.

When the access_token is not a JWT, you want to change the relevant line in the
script (look for *Print access_token*).

## Prerequisites
You will need to obtain a client_id and client_secret from the OIDC Provider and
make sure it has http(s)://localhost:PORT/index.html as one of its redirect_uri.
Put all the relevant settings in a .cnf file, such as the example
`test_oidc_client.cnf`.

## Running
`./test_oidc_client.sh myconfig.cnf`
