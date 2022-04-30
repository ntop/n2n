# Management API

This document is focused on the machine readable API interfaces.  It is a
generic document describing the protocol framing, but not the specific
messages and replies.

Both the edge and the supernode provide a management interface UDP port.
These interfaces have some documentation on their non machine readable
commands in the respective daemon man pages.

Default Ports:
- UDP/5644 - edge
- UDP/5645 - supernode

A Quick start example query:
    `echo r 1 help | nc -w1 -u 127.0.0.1 5644`

## JSON Query interface

A machine readable API is available for both the edge and supernode.  It
takes a simple text request and replies with JSON formatted data.

The request is in simple text so that the daemon does not need to include any
complex parser.

The replies are all in JSON so that the data is fully machine readable and
the schema can be updated as needed - the burden is entirely on the client
to handle different replies with different fields.  It is expected that
any client software will be written in higher level programming languages
where this flexibility is easy to provide.

Since the API is over UDP, the replies are structured so that each part of
the reply is clearly tagged as belonging to one request and there is a
clear begin and end marker for the reply.  This is expected to support the
future possibilities of pipelined and overlapping transactions.

The replies will also handle some small amount of re-ordering of the
packets, but that is not an specific goal of the protocol.

Note that this API will reply with a relatively large number of UDP packets
and that it is not intended for high frequency or high volume data transfer.
It was written to use a low amount of memory and to support incremental
generation of the reply data.

With a small amount of effort, the API is intended to be human readable,
but this is intended for debugging.

## Request API

The request is a single UDP packet containing one line of text with at least
three space separated fields.  Any text after the third field is available for
the API method to use for additional parameters

Fields:
- Message Type
- Options
- Method
- Optional Additional Parameters

The maximum length of the entire line of text is 80 octets.

All request packets should generate a reply.  However, this reply may simply
be an error.

### Message Type

This is a single octet specifying the type:

- "r" for a read-only method (or one that does not need change permissions)
- "w" for a write method (or one that makes changes)
- "s" for a subscribe method to request this socket receive some events

To simplify the interface, the reply from both read and write calls to the
same method is expected to contain the same data.  In the case of a write
call, the reply will contain the new state after making the requested change.

The subscribe and events message flow works with a different set of messages.

### Options

The options field is a colon separated set of options for this request.  Only
the first subfield (the "tag") is mandatory.  The second subfield is a set
of flags that describe which optional subfields are present.
If there are no additional subfields then the flags can be omitted.

SubFields:
- Message Tag
- Optional Message Flags (defaults to 0)
- Optional Authentication Key

#### Message Tag

Each request provides a tag value.  Any non error reply associated with this
request will include this tag value, allowing all related messages to be
collected within the client.  The tag will be truncated if needed by the
daemon, but there will be at least 8 octets of space available.

Where possible, the error replies will also include this tag, however some
errors occur before the tag is parsed.

The tag is not interpreted by the daemon, it is simply echoed back in all
the replies.  It is expected to be a short string that the client knows
will be unique amongst all recent, still outstanding or subscription requests
on a given socket.

One possible client implementation is a number between 0 and 999, incremented
for each request and wrapping around to zero when it is greater than 999.

The client is also expected to use the tag to determine the format of the
data in the reply - since the client requested that data, it also knows what
should be in the matching reply.  This is especially important with
asynchronous pub/sub events.

#### Message Flags

This subfield is a set of bit flags that are hex-encoded and describe any
remaining optional subfields.

Currently, only one flag is defined.  The presence of that flag indicates
that an authentication key subfield is also present.

Values:
- 0 - No additional subfields are present
- 1 - One additional field, containing the authentication key

#### Authentication Key

A simple string password that is provided by the client to authenticate
this request.  See the Authentication section below for more discussion.

#### Example Options value

e.g:
    `102:1:PassWord`

### Example Request string

e.g:
    `r 103:1:PassWord peer`

## Reply API

Each UDP packet in the reply is a complete and valid JSON dictionary
containing a fragment of information related to the entire reply.

Reply packets are generated both in response to requests and whenever
an event is published to a subscribed channel.

### Common metadata

There are two keys in each dictionary containing metadata.  First
is the `_tag`, containing the Message Tag from the original request.
Second is the `_type` which identifies the expected contents of this
packet.

### `_type: error`

If an error condition occurs, a packet with a `error` key describing
the error will be sent.  This usually also indicates that there will
be no more substantial data arriving related to this request.

e.g:
    `{"_tag":"107","_type":"error","error":"badauth"}`

### `_type: begin`

Before the start of any substantial data packets, a `begin` packet is
sent.  For consistency checking, the method in the request is echoed
back in the `error` key.

e.g:
    `{"_tag":"108","_type":"begin","cmd":"peer"}`

For simplicity in decoding, if a `begin` packet is sent, all attempts
are made to ensure that a final `end` packet is also sent.

### `_type: end`

After the last substantial data packet, a final `end` packet is sent
to signal to the client that this reply is finished.

e.g:
    `{"_tag":"108","_type":"end"}`

### `_type: row`

The substantial bulk of the data in the reply is contained within one or
more `row` packets.  The non metadata contents of each `row` packet is
defined entirely by the method called and may change from version to version.

Each `row` packet contains exactly one complete JSON object. The row replies
may be processed incrementally as each row arrives and no batching of multiple
packets will be required.

e.g:
    `{"_tag":"108","_type":"row","mode":"p2p","ip4addr":"10.135.98.84","macaddr":"86:56:21:E4:AA:39","sockaddr":"192.168.7.191:41701","desc":"client4","lastseen":1584682200}`

### `_type: subscribed`

Signals that the subscription request has been successfully completed.
Any future events on the requested channel will be asynchronously sent
as `event` packets using the same tag as the subscribe request.

### `_type: unsubscribed`

Only one management client can be subscribed to any given event topic, so if
another subscribe request arrives, the older client will be sent this message
to let them know that they have been replaced.

(In the future, this may also be sent as a reply to a explicit unsubscribe
request)

### `_type: replacing`

If a new subscription request will replace an existing one, this message is
sent to the new client to inform them that they have replaced an older
connection.

### `_type: event`

Asynchronous events will arrive with this message type, using the same tag as
the original subscribe request.  Just like with the `row` packets, the non
metadata contents are entirely defined by the topic and the specific n2n
version.

## Subscribe API

A client can subscribe to events using a request with the type of "s".
Once a subscribe has been successfully completed, any events published
on that channel will be forwarded to the client.

Only one management client can be subscribed to any given event topic,
with newer subscriptions replacing older ones.

The special channel "debug" will receive copies of all events published.
Note that this is for debugging of events and the packets may not have
the same tag as the debug subscription.

## Authentication

Some API requests will make global changes to the running daemon and may
affect the availability of the n2n networking.  Therefore the machine
readable API include an authentication component.

Currently, the only authentication is a simple password that the client
must provide. It defaults to 'n2n' and can manually be set through the
command line parameter `--management-password <pw>` – for edge as well
as for supernode.
