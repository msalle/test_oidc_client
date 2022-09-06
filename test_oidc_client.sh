#!/bin/bash
#

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author Mischa Sall\'e - Nikhef

# Simple OIDC RP command-line test utility
#
# configuration is in separate file: create in CWD a file test_oidc_client.cnf
# containing things like:
#
#    baseurl="https://sso.example.org"
#    localport=8000
#    localscheme=http
#    localhost="localhost"
#    clientid="blablabla"
#    clientsecret="secretsecretsecret"
#    scopes="openid profile email"
#    firefox=/c/Program\ Files/Mozilla\ Firefox/firefox.exe
#

config=${1:-test_oidc_client.cnf}
[ -e $config ] && . $config

# max time (sec) for the user to finish login
timeout=100

# base URL, used for retrieving the .well-known/openid-configuration
baseurl=${baseurl:-https://sso.example.org}

# temporary files
formfile=authorize.html
indexfile=index.html
logfile=server.log
serverpy=server.py

# default serverpid is unset
serverpid=""

# redirect endpoint, will be served using SimpleHTTPServer
port=${localport:-8000}
scheme=${localscheme:-http}
redirecturi=${scheme}://${localhost:-localhost}:$port/$indexfile

# client_id & client_secret
clientid=${clientid:-'PUBLIC'}
clientsecret=${clientsecret:-'SECRET'}

# access token is JWT?
at_is_jwt=${at_is_jwt:-0}

if [ $clientid == PUBLIC -o $clientsecret == SECRET ]; then
  echo "You need a clientID and clientSecret" >&2
  exit 1
fi

# requested scopes
scopes=${scopes:-"openid profile email"}

# webbrowser and default options
browser="${browser:-firefox}"
browser_opts="${browser_opts:---private-window}"

# define curlopt to set extra curl options for /.well-known, /token and
# /userinfo, e.g. -v -k
curlopt="${curlopt:-}"


########################################################################
# Helper functions
########################################################################

# Cleanup function: removes tempfiles, tempdir and kill python webserver
cleanup()   {
    if [ -n "$serverpid" ];then
	echo "Killing local webserver $serverpid" >&2
	kill $serverpid
	wait $serverpid 2> /dev/null
    fi
    rm -f $formfile $indexfile $logfile $serverpy
    cd ..
    rmdir $(basename $tempdir)
}

# automatically cleanup files and server process upon exit
trap cleanup EXIT

# Prints header and content of a JWT
decode_jwt()	{
    rc=0
    echo "Header:"
    echo "$1" | cut -d. -f1 | base64 -d | json_pp || {
	echo "Not a JWT header:" >&2
	echo "\"$1\"" >&2
	rc=1
    }
    echo "Payload:"
    echo "$1" | cut -d. -f2 | base64 -d | json_pp || {
	echo "Not a JWT payload:" >&2
	echo "\"$1\"" >&2
	rc=1
    }
    return $rc
}

# Prints a JSON
json_print()	{
    echo "$1" | json_pp || {
	echo "Not a JSON:" >&2
	echo "$1" >&2
	return 1
    }
    return 0
}

# Get value for given key from JSON object, note: better with jq and some proper
# json parsing
json_get()  {
    echo "$1"|json_pp|grep "\"$2\""|head -1|cut -d'"' -f4
}

# Starts a (localhost) http(s) server
python_http_server()	{
    python -V 2>&1 | grep -q 'Python 2' && {
	class1=BaseHTTPServer; class2=SimpleHTTPServer
    } || {
	class1=http.server; class2=http.server
    }

    if [ "$scheme" = "http" ];then
	httpd_socket=""
    elif [ "$scheme" = "https" ];then
	httpd_socket="httpd.socket = ssl.wrap_socket (httpd.socket, keyfile='$keyfile', certfile='$certfile', ca_certs='$ca_certs', server_side=True)"
    else
	echo "scheme \"$scheme\" is invalid (should be http or https)" >&2
	return 1
    fi
    
    cat > $serverpy << EOF
#!/usr/bin/python
from $class1 import HTTPServer
from $class2 import SimpleHTTPRequestHandler
import ssl
import sys, io
# For python3 we need to disable buffered output
if sys.version_info.major>2:
    sys.stderr = io.TextIOWrapper(open(sys.stderr.fileno(), 'wb', 0), write_through=True)

httpd = HTTPServer(('$localhost', $port), SimpleHTTPRequestHandler)
# In case of HTTPS, config the cert/key here
$httpd_socket
httpd.serve_forever()
EOF
    
    python ./server.py > /dev/null 2> $logfile &
    # set (global) PID of the python process.
    serverpid=$!
    # short sleep to let python log errors: could e.g. have port in use...
    sleep 0.5
    if grep -q 'Traceback' $logfile;then
	cat $logfile >&2
	return 1
    fi
    return 0
}

# Make runtime temp dir
tempdir=$(mktemp --tmpdir -d testXXXXXX)
cd $tempdir


# Now get the config from .well-known/openid-configuration
metadata=$(curl $curlopt -sS ${baseurl}/.well-known/openid-configuration) || exit
echo "openid-configuration:"
json_print "$metadata" || exit

# get the endpoints from the openid config
authorization_endp=$(json_get "$metadata" "authorization_endpoint")
token_endp=$(json_get "$metadata" "token_endpoint")
userinfo_endp=$(json_get "$metadata" "userinfo_endpoint")

# Manually set getcert endpoint
echo Authorization endpoint: $authorization_endp
echo Token endpoint: $token_endp
echo Userinfo endpoint: $userinfo_endp

########################################################################
# Main flow starts here
########################################################################

# Create random state
state=$(openssl rand -hex 9)

# Make a submit page on the fly, using obtained client_id and secret
cat > $formfile << EOF
<html>
<title>Authorization flow</title>
<form action="$authorization_endp" method=get>
<input type=hidden name=scope value="$scopes">
<input type=hidden name=response_type value="code">
<input type=hidden name=client_id value="$clientid">
<input type=hidden name=redirect_uri value="$redirecturi">
<input type=hidden name=state value="$state">
<input type=submit value="start authorization request">
</form>
</html>
EOF

# Make return page on the fly
cat > $indexfile << EOF
Please return to cmdline (you can close this window)
EOF

# Start web server, dump output to logfile
echo;echo "Starting listening webserver"
python_http_server
[ $? -ne 0 ] && exit
echo "webserver (pid $serverpid) listening on $scheme://$localhost:$port/"

# Start /authorize request
echo;echo "Spawning webbrowser"
"${browser}" "${browser_opts}" $formfile &

# Wait for the user to return
echo "Waiting for code till $(date +%H:%M:%S -d "now + $timeout seconds")..."
errpattern='^.*'${indexfile}'?\(error=.*\)$'
pattern='^.*'${indexfile}'.*[?&]\+code=\([^ &]\+\)[ &].*$'
for ((i=0; i<=$timeout; i++));do
    grep -q "$pattern" $logfile && break
    grep -q "$errpattern" $logfile && {
	echo "Error: " >&2
	sed -n "s/$errpattern/\1/p" $logfile|tr '&' '\n' >&2
	exit
    }
    if [ $i -eq $timeout ];then
	echo "Timed out )-:"
	exit
    fi
    sleep 1
done

# Get code (authorization grant) from server's logfile
code=$(sed -n "s/$pattern/\1/p" $logfile)
echo;echo "Code: \"$code\""

# Do /token request using authorization grant
# NOTE: don't use --user
#    --user $clientid:$clientsecret
# since it gets truncated when longer than (...) bytes using older curl clients
echo "Running: curl code request at token endpoint ${token_endp}"
response=$(curl $curlopt -sS \
    -d "grant_type=authorization_code" \
    -d "code=$code" \
    -d "redirect_uri=$redirecturi" \
    -d "client_id=$clientid" \
    -d "client_secret=$clientsecret" \
    ${token_endp})
echo;date
echo "token response:"
json_print "$response" || exit

# Get access_token and id_token from the response
access_token=$(json_get "$response" "access_token")
id_token=$(json_get "$response" "id_token")
refresh_token=$(echo $response|json_pp|grep '"refresh_token"'|cut -d'"' -f4)

# Print id_token content header and content
echo;echo "id_token:"
decode_jwt $id_token

# Print access_token header and content
echo;echo "access_token:"
if [ $at_is_jwt -eq 1 ];then
    decode_jwt $access_token
else
    echo $access_token
fi
echo

# Do userinfo request and print
echo;echo "userinfo:"
echo "Running: curl userinfo request at ${userinfo_endp} using Authorization: Bearer header"
userinfo=$(curl $curlopt -sS \
    --header "Authorization: Bearer $access_token" \
    ${userinfo_endp})
echo;echo "userinfo response:"
json_print "$userinfo" || exit
echo

# Do refresh token and print
#echo;echo "refresh token:"
#echo "Running: curl refresh_token request at ${token_endp} using Authorization: Bearer header"
#response=$(curl $curlopt -sS \
#    --header "Authorization: Bearer $access_token" \
#    -d "grant_type=refresh_token" \
#    -d "refresh_token=$refresh_token" \
#    -d "client_id=$clientid" \
#    -d "client_secret=$clientsecret" \
#    ${token_endp})
#echo;date
#echo "token response:"
#json_print "$response" || exit
#echo
