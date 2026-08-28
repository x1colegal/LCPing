# lcpping

`lcpping` is a small LCP Echo utility for OpenWrt/PPPoE connections.

It works similarly to the traditional `ping` command, but instead of sending
ICMP Echo Requests, it sends PPP LCP Echo-Requests directly through the active
PPPoE session and measures the corresponding LCP Echo-Replies.

The utility is written in ucode and uses Linux `AF_PACKET` raw sockets.

## Features

- Sends real PPP LCP Echo-Requests
- Receives and validates LCP Echo-Replies
- Automatically detects:
  - PPPoE interface
  - PPPoE Session-ID
  - local Ethernet MAC address
  - Access Concentrator / peer MAC address
  - local negotiated LCP Magic-Number
- Caches the detected Magic-Number for the current PPPoE session
- Automatically invalidates the cache when the PPPoE Session-ID changes
- Runs continuously by default, like `ping`
- Clean Ctrl+C handling
- Waits for an already transmitted Echo-Request before exiting
- RTT statistics:
  - minimum
  - average
  - maximum
  - mdev
- Packet loss statistics
- Configurable interval and timeout
- No Python dependency
- No external packet generator required

## Requirements

- OpenWrt
- ucode
- Linux `AF_PACKET` support
- An active PPPoE connection
- Root privileges

The script reads the active PPPoE session from:

    /proc/net/pppoe

## Installation

Copy `lcpping.uc` to the OpenWrt router:

    scp -O lcpping.uc root@[ROUTER_IPV6]:/root/lcpping.uc

Then make it executable:

    chmod +x /root/lcpping.uc

## Usage

Run continuously:

    /root/lcpping.uc

Example output:

    Detecting local LCP Magic-Number on br-lan... 0x12345678
    LCP PING 02:11:22:33:44:55 via br-lan: session=0x1234 magic=0x12345678
    30 bytes from 02:11:22:33:44:55: lcp_seq=1 id=1 magic=0x87654321 time=3.101 ms
    30 bytes from 02:11:22:33:44:55: lcp_seq=2 id=2 magic=0x87654321 time=2.574 ms
    30 bytes from 02:11:22:33:44:55: lcp_seq=3 id=3 magic=0x87654321 time=2.647 ms
    ^C

    --- 02:11:22:33:44:55 LCP ping statistics ---
    3 packets transmitted, 3 received, 0.0% packet loss
    rtt min/avg/max/mdev = 2.574/2.774/3.101/0.232 ms

## Options

    -c COUNT

Stop after sending `COUNT` Echo-Requests.

Example:

    /root/lcpping.uc -c 5

---

    -i INTERVAL

Set the interval between Echo-Requests, in seconds.

Default:

    1

Examples:

    /root/lcpping.uc -i 2
    /root/lcpping.uc -i 0.5
    /root/lcpping.uc -i 0.02

---

    -W TIMEOUT

Set the maximum time to wait for an Echo-Reply.

Example:

    /root/lcpping.uc -W 2

---

    -q

Quiet mode.

---

    -h

Display usage information.

## Ctrl+C behavior

When Ctrl+C is pressed while no Echo-Request is pending, `lcpping` exits
immediately.

If an Echo-Request has already been transmitted, `lcpping` stops sending new
requests but waits for the pending Echo-Reply.

The pending request is then counted normally as either a reply or a timeout
before the final statistics are printed.

This avoids reporting artificial packet loss simply because the program was
terminated immediately after transmitting a request.

## LCP Magic-Number detection

PPP LCP Echo packets contain a negotiated Magic-Number.

`lcpping` needs the local Magic-Number in order to construct valid
LCP Echo-Requests.

During initial discovery, the utility opens an `AF_PACKET` capture socket and
observes locally generated LCP traffic from the active PPPoE session.

Once detected, the value is cached in:

    /root/.lcpping-magic

The cache contains the PPPoE Session-ID and corresponding Magic-Number.

Example:

    1234 12345678

The cached Magic-Number is used only while the current PPPoE Session-ID matches
the cached Session-ID.

After PPPoE reconnects and receives another Session-ID, the old cache is
automatically rejected and discovery is performed again.

To manually force rediscovery:

    rm -f /root/.lcpping-magic
    /root/lcpping.uc

## Important OpenWrt configuration

Some OpenWrt versions start `pppd` with:

    lcp-echo-adaptive

When this option is enabled, `pppd` may suppress periodic LCP Echo-Requests
while other traffic is being received.

This makes initial Magic-Number discovery unreliable because there may be no
local LCP Echo packet during the discovery window.

You can check the active pppd command with:

    ps w | grep '[p]ppd'

For reliable automatic discovery, periodic LCP Echo-Requests should be enabled
without `lcp-echo-adaptive`.

On affected OpenWrt installations, the option may be added by:

    /lib/netifd/proto/ppp.sh

For example, the script may contain:

    local lcp_adaptive="lcp-echo-adaptive"

Changing it to:

    local lcp_adaptive=""

prevents netifd from passing `lcp-echo-adaptive` to pppd.

Before modifying the file, create a backup:

    cp /lib/netifd/proto/ppp.sh /root/ppp.sh.backup

Then:

    sed -i 's/local lcp_adaptive="lcp-echo-adaptive"/local lcp_adaptive=""/' /lib/netifd/proto/ppp.sh

Reconnect PPPoE:

    ifdown wan
    ifup wan

Then verify:

    ps w | grep '[p]ppd'

A typical resulting command should still include options such as:

    lcp-echo-interval 1
    lcp-echo-failure 5

but should no longer contain:

    lcp-echo-adaptive

Note that `/lib/netifd/proto/ppp.sh` is part of the OpenWrt system and this
modification may be overwritten by package upgrades or firmware upgrades.

## How it works

The program constructs the complete Ethernet + PPPoE + PPP + LCP frame.

The packet contains:

    Ethernet
      |
      +-- EtherType 0x8864
            |
            +-- PPPoE Session
                  |
                  +-- PPP protocol 0xc021
                        |
                        +-- LCP Echo-Request

LCP Echo-Request:

    Code        9
    Identifier  1..255
    Length      8
    Magic       local negotiated Magic-Number

LCP Echo-Reply:

    Code        10
    Identifier  matching request identifier
    Length      8
    Magic       peer negotiated Magic-Number

The LCP Identifier cycles through:

    1 ... 255, 1 ... 255

independently from the displayed `lcp_seq` counter.

## Example

A real PPPoE session may look like:

    LCP PING 02:11:22:33:44:55 via br-lan: session=0x1234 magic=0x12345678

where:

    02:11:22:33:44:55

is the PPPoE peer / Access Concentrator MAC,

    0x1234

is the PPPoE Session-ID,

and:

    0x12345678

is the locally negotiated LCP Magic-Number.

An Echo-Reply such as:

    magic=0x87654321

contains the peer's negotiated Magic-Number.

## License

No license has been selected yet.
