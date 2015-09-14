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
credentials (name/password), or will receive a [401 Unauthorized](#401-unauthorized)
response.

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

The lingua franca of the HTTP REST API is [JSON][] in [UTF-8][] encoding.  All
Serval DNA HTTP REST responses have a Content-Type of **application/json**
unless otherwise documented.

Some responses contain non-standard HTTP headers as part of the result they
return to the client; for example, [Rhizome response headers](#rhizome-response-headers).

#### JSON result

All responses that convey no special content return the following *JSON result*
object:

    {
     "http_status_code": ...,
     "http_status_message": "..."
    }

The `http_status_code` field is an integer equal to the [status code][] that
follows the `HTTP/1.0` token in the first line of the response.

The `http_status_message` field is usually the same as the *reason phrase* text
that follows the code in the first line of the HTTP response.  This reason
phrase may be a [standard phrase][status code], or it may be more explanatory;
for example, *403 Forbidden* responses from Rhizome use the phrase, “Rhizome
operation failed”.

[status code]: http://www.w3.org/Protocols/HTTP/1.0/spec.html#Status-Codes

Some responses augment the *JSON result* object with extra fields; for example,
[Rhizome JSON result](#rhizome-json-result).

#### 401 Unauthorized

If a request does not supply an "Authorization" header with a recognised
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

Many HTTP REST responses that return a list of regular objects (eg, [GET
/restful/rhizome/bundlelist.json](#get-restfulrhizomebundlelistjson)) use the
following *JSON table* format:

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

A Rhizome *bundle* consists of a single *manifest* and an optional *payload*.

TBC

### Rhizome response headers

All Rhizome requests that fetch or insert a single bundle, whatever the
outcome, contain the following HTTP headers in the response:

    Serval-Rhizome-Result-Bundle-Status-Code: -1|0|1|2|3|4|5|6|7
    Serval-Rhizome-Result-Bundle-Status-Message: <text>
    Serval-Rhizome-Result-Payload-Status-Code: -1|0|1|2|3|4|5|6|7|8
    Serval-Rhizome-Result-Payload-Status-Message: <text>

*  the `Serval-Rhizome-Result-Bundle-Status-Code` header is the integer [bundle
   status code](#bundle-status-code)
*  the `Serval-Rhizome-Result-Bundle-Status-Message` header is the string
   [bundle status message](#bundle-status-message)
*  the `Serval-Rhizome-Result-Payload-Status-Code` header is the integer
   [payload status code](#payload-status-code)
*  the `Serval-Rhizome-Result-Payload-Status-Message` header is the string
   [payload status message](#payload-status-message)

### Rhizome response bundle headers

All Rhizome requests that *successfully* fetch or insert a single bundle
contain the following HTTP headers in the response, which convey the core
manifest fields:

    Serval-Rhizome-Bundle-Id: <hex64bid>
    Serval-Rhizome-Bundle-Version: <integer>
    Serval-Rhizome-Bundle-Filesize: <integer>

If *filesize* is not zero, then the following HTTP header is present:

    Serval-Rhizome-Bundle-Filehash: <hex128>

If the bundle is a *journal*, then the following HTTP header is present:

    Serval-Rhizome-Bundle-Tail: <integer>

In addition, none, some or all of the following HTTP headers may be present, to
convey optional fields that are present in the bundle's manifest:

    Serval-Rhizome-Bundle-Sender: <hex64sid>
    Serval-Rhizome-Bundle-Recipient: <hex64sid>
    Serval-Rhizome-Bundle-BK: <hex64>
    Serval-Rhizome-Bundle-Crypt: 0 or 1
    Serval-Rhizome-Bundle-Service: <token>
    Serval-Rhizome-Bundle-Name: <quotedstring>
    Serval-Rhizome-Bundle-Date: <integer>

If the bundle's author, as verified by its signature, is present in the keyring,
then the following HTTP header is present:

    Serval-Rhizome-Bundle-Author: <hex64sid>

If the bundle's secret is known, either because it was supplied in the request
or was deduced from the manifest's Bundle Key (BK) field and the author's
Rhizome Secret (RS), then the following HTTP header is present:

    Serval-Rhizome-Bundle-Secret: <hex64>

The following HTTP headers might be present at the sole discretion of the
server, but they are not guaranteed, and future upgrades of [Serval DNA][] may
remove them.  They reveal internal details of the storage of the bundle:

    Serval-Rhizome-Bundle-Rowid: <integer>
    Serval-Rhizome-Bundle-Inserttime: <integer>

### Rhizome JSON result

All Rhizome requests to fetch or insert a single bundle that do not produce a
special response content for the outcome, return the following augmented [JSON
result](#json-result) object as the HTTP response content:

    {
     "http_status_code": ...,
     "http_status_message": "...",
     "rhizome_bundle_status_code": ...,
     "rhizome_bundle_status_message": "...",
     "rhizome_payload_status_code": ...,
     "rhizome_payload_status_message": "..."
    }

*  the `rhizome_bundle_status_code` field is the integer [bundle status code](#bundle-status-code)
*  the `rhizome_bundle_status_message` field is the string [bundle status message](#bundle-status-message)
*  the `rhizome_payload_status_code` field is the integer [payload status code](#payload-status-code)
*  the `rhizome_payload_status_message` field is the string [payload status message](#payload-status-message)

#### Bundle status code

All Rhizome operations that involve fetching and/or inserting a single manifest
into the Rhizome store return a *bundle status code*, which describes the
outcome of the operation.  Some codes have different meanings in the context of
a fetch or an insertion, and some codes can only be produced by insertions.

| code | meaning                                                                         |
|:----:|:------------------------------------------------------------------------------- |
|  -1  | internal error                                                                  |
|   0  | "new"; (fetch) bundle not found; (insert) bundle added to store                 |
|   1  | "same"; (fetch) bundle found; (insert) bundle already in store                  |
|   2  | "duplicate"; (insert only) duplicate bundle already in store                    |
|   3  | "old"; (insert only) newer version of bundle already in store                   |
|   4  | "invalid"; (insert only) manifest is invalid                                    |
|   5  | "fake"; (insert only) manifest signature is invalid                             |
|   6  | "inconsistent"; (insert only) manifest filesize/filehash does not match payload |
|   7  | "no room"; (insert only) doesn't fit; store may contain more important bundles  |
|   8  | "readonly"; (insert only) cannot modify manifest because secret is unknown      |
|   9  | "busy"; Rhizome store database is currently busy (re-try)                       |

#### Bundle status message

The *bundle status message* is a short English text that explains the meaning
of its accompanying *bundle status code*, to assist with diagnosis.  The
message for a code may differ across requests and may change when [Serval
DNA][] is upgraded, so it cannot be relied upon as a means to programmatically
detect the outcome of an operation.

#### Payload status code

All Rhizome operations that involve fetching and/or inserting a single payload
into the Rhizome store return a *payload status code*, which describes the
outcome of the payload operation, and elaborates on the the reason for the
accompanying *bundle status code*.  Some codes have different meanings in the
context of a fetch or an insertion, and some codes can only be produced by
insertions.

| code | meaning                                                               |
|:----:|:--------------------------------------------------------------------- |
|  -1  | internal error                                                        |
|   0  | empty payload (zero length)                                           |
|   1  | (fetch) payload not found; (insert) payload added to store            |
|   2  | (fetch) payload found; (insert) payload already in store              |
|   3  | payload size does not match manifest *filesize* field                 |
|   4  | payload hash does not match manifest *filehash* field                 |
|   5  | payload key unknown: (fetch) cannot decrypt; (insert) cannot encrypt  |
|   6  | (insert only) payload is too big to fit in store                      |
|   7  | (insert only) payload evicted; other payloads are ranked higher       |

#### Payload status message

The *payload status message* is short English text that explains the meaning of
its accompanying *payload status code*, to assist diagnosis.  The message for a
code may differ across requests and may change when [Serval DNA][] is upgraded,
so it cannot be relied upon as a means to programmatically detect the outcome
of an operation.

### GET /restful/rhizome/bundlelist.json

TBC

### GET /restful/rhizome/newsince/TOKEN/bundlelist.json

TBC

### GET /restful/rhizome/BID.rhm

Fetches the manifest for the bundle whose id is `BID` (64 hex digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE.rhm

If the **manifest is found** in the local Rhizome store, then the response will
be *200 OK* and:
*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found bundle, some of which is duplicated from the
   manifest
*  the response's Content-Type is **rhizome/manifest; format=text+binarysig**
*  the response's Content-Length is the size, in bytes, of the manifest with
   its binary signature appended
*  the response's content is the Rhizome manifest in text format followed by a
   nul (0) byte followed by the manifest's binary signature

If the **manifest is not found** in the local Rhizome store, then the response
will be *403 Forbidden* and:
*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) are
   absent from the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/raw.bin

Fetches the "raw" (encrypted) payload for the bundle whose id is `BID` (64 hex
digits), eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/raw.bin

If the **manifest and the payload are both found** in the local Rhizome store,
then the response will be *200 OK* and:
*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code) will be 0 if the payload has
   zero length, otherwise 2
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found bundle, some of which is duplicated from the
   manifest
*  the response's Content-Type is **application/octet-stream**
*  the response's Content-Length is the size, in bytes, of the raw payload
*  the response's content is the bundle's payload exactly as stored in Rhizome;
   if the payload is encrypted (the manifest's `crypt` field is 1) then the
   payload is not decrypted

If the **manifest is found** in the local Rhizome store but the **payload is
not found**, then the response will be *403 Forbidden* and:
*  the [bundle status code](#bundle-status-code) will be 1
*  the [payload status code](#payload-status-code) will be 1
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found manifest
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

If the **manifest is not found** in the local Rhizome store, then the response
will be *403 Forbidden* and:
*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code), if present in the response,
   is not relevant, so must be ignored
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) are
   absent from the response
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

### GET /restful/rhizome/BID/decrypted.bin

Fetches the decrypted payload for the bundle whose id is `BID` (64 hex digits),
eg:

    /restful/rhizome/1702BD647D614DB72C36BD634B6870CA31040C2EEC5069AEC0C0841D0CC671BE/decrypted.bin

The responses are identical to those for [GET /restful/rhizome/BID/raw.bin](get-restful-rhizome-bid-raw-bin),
with the following additional case:

If the **manifest and payload are both found** and the payload is **encrypted**
(the manifest's `crypt` field is 1), but the **payload secret is not known**,
then:
*  the [bundle status code](#bundle-status-code) will be 0
*  the [payload status code](#payload-status-code) will be 5
*  the [Rhizome response bundle headers](#rhizome-response-bundle-headers) give
   information about the found manifest
*  the response's content is the [Rhizome JSON result](#rhizome-json-result)
   object

For a bundle that has a *sender* and a *recipient*, the payload secret is
determined as follows:
*  if the recipient's identity is found (unlocked) in the keyring, then the
   secret is derived from the recipient's private key; otherwise
*  if the recipient's identity is not found in the keyring (locked or missing)
   but the sender's identity is found (unlocked) in the keyring, then the
   secret is derived from the sender's private key; otherwise
*  neither identity is found in the keyring (both are locked or missing), so
   the payload secret is unknown.

For all other bundles, the payload secret is derived from the Bundle Secret.
*  if the correct Bundle Secret was supplied in the request then the payload
   secret is derived from it directly; otherwise
*  if the manifest contains a `BK` field, and the bundle's author can be
   deduced from the manifest's signature and the author's identity is found
   (unlocked) in the keyring, then the Bundle Secret is derived from the BK
   field and the author's Rhizome Secret, then the payload secret is derived
   from that; otherwise
*  the Bundle Secret is unknown, so the payload secret is unknown.

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
