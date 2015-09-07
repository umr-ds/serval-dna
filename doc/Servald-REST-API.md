Serval DNA REST API
===================
[Serval Project][], September 2015

Introduction
------------

The [Serval DNA][] daemon that runs on every node in a Serval Mesh network
gives applications access to the network through two main [API][]s:

  * for "traditional" packet transport, applications use the [MDP API][MDP] and
    [MSP API][MSP] to send and receive Serval network packets to and from
    nearby nodes with latencies of up to several seconds;

  * for store-and-forward content distribution and transport, applications use
    the [HTTP REST][] API described by this document to send, share and receive
    files ([Rhizome][]) and messages ([MeshMS][]) between nearby or distant
    nodes, with latencies that could be up to days or even months.

The HTTP REST API also allows applications to manage Serval identities on the
local node.  The Serval mesh network uses identities as network addresses.

### Protocol and port

The Serval DNA [HTTP REST][] API is an [HTTP 1.0][] server that accepts
requests on the loopback interface (IPv4 address 127.0.0.1), TCP port 4110.  It
rejects requests that do not originate on the local host.

### Security

The REST API is a clear-text interface; requests and responses are *not*
encrypted.  HTTP REST is not carried over any physical network link so it is
not exposed to remote eavesdroppers.  That means the only threat comes from
local processes.

Linux prevents normal processes from accessing the traffic on local sockets
between other processes, so to attack Serval DNA and its clients, a local
process on the local host would have to gain super-user privilege (eg, through
a privilege escalation vulnerability), which would give it many avenues for
attacking Serval DNA and its clients.  In this situation, encrypting
client-server communications would offer no protection whatsoever.

### Authentication

Clients of the HTTP REST API must authenticate themselves using [Basic
Authentication][].  This narrows the window for opportunistic attacks on the
HTTP port by malicious applications that scan for open local ports to exploit.
Any process wishing to use the REST API must supply valid authentication
credentials (name/password), or will receive a *401 Unauthorized* response.

Client applications obtain their REST API credentials via a back channel
specific to their particular platform.  This delegates the exercise of handing
out credentials to the application layer, where users can (usually) exercise
their own discretion.  For example, on Android, a client app sends an
[Intent][] to the [Serval Mesh][] app requesting a Serval REST credential, and
will receive a reply only if it possesses the right Android [Permission][].
When users install or run the client app, Android informs them that the app
requests the "Serval Network" permission, and users may allow or deny it.

As a fall-back mechanism, created primarily to facilitate testing, HTTP REST
API credentials can be [configured][] using configuration options of the form:

    api.restful.users.USERNAME.password=PASSWORD

PASSWORD is a cleartext secret, so the Serval DNA configuration file must be
protected from unauthorised access or modification by other apps.  That makes
this mechanism unsuitable for general use.

### Requests

An HTTP REST request is a normal [HTTP 1.0][] GET or POST request.

*   A **GET** request consists of an initial "GET" line, followed by zero or
    more header lines, followed by a blank line.  As usual for HTTP, all lines
    are terminated by an ASCII CR-LF sequence.

    For example:

        GET /restful/keyring/identities.json?pin=1234 HTTP/1.0
        Authorization: Basic aGFycnk6cG90dGVy
        Accept: */*
        

*   A **POST** request is the same as a GET request except that the first word
    of the first line is "POST", the blank line is followed by a request body,
    and the following request headers are mandatory:

    *   **Content-Length** gives the exact number of bytes (octets) in the
        body, and must be correct.  Serval DNA will not process the request
        until it receives Content-Length bytes, so if Content-Length is too
        large, the request will suspend and eventually time out.  Serval DNA
        will ignore any bytes received after it has read Content-Length bytes,
        so if Content-Length is too small, the request body will be malformed.

    *   **Content-Type** gives the [Internet Media Type][] of the body.  Serval
        DNA currently supports the following media types in requests:
        *   **multipart/form-data; boundary=** is used to send large parameters
            in POST requests
        *   **text/plain; charset=utf-8** is used for [MeshMS][] message form
            parts
        *   **rhizome/manifest; format=text+binarysig** is used for [Rhizome][]
            manifest form parts

### Responses

An HTTP REST response is a normal [HTTP 1.0][] response consisting of a header
block, a blank line, and an optional body, for example: As usual, all lines are
terminated by an ASCII CR-LF sequence.  For example:

    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 78

    {
     "http_status_code": 200,
     "http_status_message": "OK"
    }

The lingua franca of the HTTP REST API is [JSON][] in [UTF-8][] encoding, so
all Serval DNA HTTP REST responses have a Content-Type of **application/json**
unless otherwise documented.

If the request does not supply an "Authorization" header with a recognised
credential, the response will be *401 Unauthorized* with a "WWW-Authenticate"
header:

    HTTP/1.0 401 Unauthorized
    Content-Type: application/json
    Content-Length: 88
    WWW-Authenticate: Basic "Serval RESTful API"

    {
     "http_status_code": 401
     "http_status_message": "Unauthorized"
    }

### JSON table

HTTP REST responses that return a list of regular objects (eg, [GET
/restful/rhizome/bundlelist.json](#get-restfulrhizomebundlelistjson)) use the
following "JSON table" format:

    {
        "header":["fieldname1","fieldname2","fieldname3", ... ],
        "rows":[
            [field1, field2, field3, ... ],
            [field1, field2, field3, ... ],
            ...
        ]
    }

The JSON table format is more compact than the most straightforward JSON
representation, an array of JSON objects, which has the overhead of redundantly
repeating all field labels in every single object:

    [
        {
            "fieldname1: field1,
            "fieldname2: field2,
            "fieldname3: field3,
            ...
        },
        {
            "fieldname1: field1,
            "fieldname2: field2,
            "fieldname3: field3,
            ...
        },
        ...
    ]



A JSON table can easily be transformed into its equivalent array of JSON
objects.  The [test scripts](./testdefs_json.sh) use the following [jq(1)][]
expression to perform the transformation:

    [
        .header as $header |
        .rows as $rows |
        $rows | keys | .[] as $index |
        [ $rows[$index] as $d | $d | keys | .[] as $i | {key:$header[$i], value:$d[$i]} ] |
        from_entries |
        .["__index"] = $index
    ]

Keyring REST API
----------------

The Keyring REST API allows client applications to query, unlock, lock, create,
and modify Serval Identities in the keyring.

### Identity unlocking

All Keyring API requests can supply a password using the optional **pin**
parameter, which unlocks all keyring identities protected by that password
prior to performing the request.  Serval DNA caches every password it receives
until the password is revoked using the *lock* request, so once an identity is
unlocked, it remains visible until explicitly locked.

Identities with an empty password are permanently unlocked, and cannot be
locked.

### GET /restful/keyring/identities.json

Returns a list of all currently unlocked identities, in [JSON
table](#json-table) format.  The table columns are:

*   **sid**: the [SID][] of the identity, a string of 64 hex digits
*   **did**: the optional [DID][] (telephone number) of the identity, either
    *null* or a string of five or more digits from the set `123456789#0*`
*   **name**: the optional name of the identity, either *null* or a non-empty
    string of [UTF-8] characters

### GET /restful/keyring/add

Creates a new identity with a random [SID][].  If the **pin** parameter is
supplied, then the new identity will be protected by that password, and the
password will be cached by Serval DNA so that the new identity is unlocked.

### GET /restful/keyring/SID/set

Sets the [DID][] and/or name of the unlocked identity that has the given
[SID][].  The following parameters are recognised:

*   **did**: sets the DID (phone number); must be a string of five or more
    digits from the set `123456789#0*`
*   **name**: sets the name; must be non-empty

If there is no unlocked identity with the given SID, this request returns *404
Not Found*.

Rhizome REST API
----------------

TBC

### GET /restful/rhizome/bundlelist.json

TBC

### GET /restful/rhizome/newsince/TOKEN/bundlelist.json

TBC

### GET /restful/rhizome/BID.rhm

TBC

### GET /restful/rhizome/BID/raw.bin

TBC

### GET /restful/rhizome/BID/decrypted.bin

TBC

### POST /restful/rhizome/insert

TBC

MeshMS REST API
---------------

TBC

### GET /restful/meshms/RECIPIENTSID/conversationlist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/messagelist.json

TBC

### GET /restful/meshms/SENDERSID/RECIPIENTSID/newsince/TOKEN/messagelist.json

TBC

### POST /restful/meshms/SENDERSID/RECIPIENTSID/sendmessage

TBC


-----
**Copyright 2015 Serval Project Inc.**  
![CC-BY-4.0](./cc-by-4.0.png)
Available under the [Creative Commons Attribution 4.0 International licence][CC BY 4.0].


[Serval Project]: http://www.servalproject.org/
[CC BY 4.0]: ../LICENSE-DOCUMENTATION.md
[Serval DNA]: ../README.md
[Serval Mesh]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:servalmesh:development
[Rhizome]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:rhizome
[MeshMS]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:meshms
[MDP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:mdp
[MSP]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:msp
[SID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:sid
[DID]: http://developer.servalproject.org/dokuwiki/doku.php?id=content:tech:did
[Basic Authentication]: https://en.wikipedia.org/wiki/Basic_access_authentication
[API]: https://en.wikipedia.org/wiki/Application_programming_interface
[HTTP REST]: https://en.wikipedia.org/wiki/Representational_state_transfer
[HTTP 1.0]: http://www.w3.org/Protocols/HTTP/1.0/spec.html
[Intent]: http://developer.android.com/reference/android/content/Intent.html
[Permission]: https://developer.android.com/preview/features/runtime-permissions.html
[configured]: ./Servald-Configuration.md
[Internet Media Type]: https://www.iana.org/assignments/media-types/media-types.xhtml
[JSON]: https://en.wikipedia.org/wiki/JSON
[UTF-8]: https://en.wikipedia.org/wiki/UTF-8
[jq(1)]: https://stedolan.github.io/jq/
