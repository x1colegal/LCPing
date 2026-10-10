#!/usr/bin/ucode

import * as fs from 'fs';
import * as socket from 'socket';
import { pack, unpack } from 'struct';

/*
 * lcpping.uc
 *
 * LCP Echo "ping" for an active PPPoE session.
 *
 * Default:
 *   run forever until Ctrl+C
 *
 * Options:
 *   -c COUNT       stop after COUNT requests
 *   -i INTERVAL    interval in seconds (default: 1)
  -if INTERVAL   flood mode; send without waiting for replies
 *   -W TIMEOUT     reply timeout in seconds (default: 3)
 *   -q             quiet
 *   -h             help
 *
 * Magic Number:
 *   cached in /root/.lcpping-magic
 *   cache is tied to the current PPPoE Session-ID.
 */

const ETH_P_PPP_SES = 0x8864;
const PPP_LCP       = 0xc021;

const LCP_ECHO_REQUEST = 9;
const LCP_ECHO_REPLY   = 10;

const DEFAULT_INTERVAL = 1.0;
const DEFAULT_TIMEOUT  = 3.0;

const MAGIC_DETECT_TIMEOUT = 3;
const MAGIC_CACHE = '/root/.lcpping-magic';


/*
 * ------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------
 */

function die(msg) {
warn(`lcpping: ${msg}\n`);
exit(1);
}

function trim(s) {
return replace(s, /^\s+|\s+$/g, '');
}

function now_ns() {
let t = clock(true);

return (t[0] * 1000000000) + t[1];
}

function ns_to_ms(ns) {
return ns / 1000000.0;
}

function sec_to_ns(sec) {
return sec * 1000000000.0;
}


/*
 * ------------------------------------------------------------
 * Byte order
 * ------------------------------------------------------------
 */

const LITTLE_ENDIAN =
pack('=H', 0x0102) == pack('<H', 0x0102);

function htons16(v) {
v &= 0xffff;

if (!LITTLE_ENDIAN)
return v;

return ((v & 0x00ff) << 8) |
       ((v & 0xff00) >> 8);
}


/*
 * ------------------------------------------------------------
 * MAC conversion
 * ------------------------------------------------------------
 */

function mac_bytes(mac) {
let p = split(mac, ':');

if (length(p) != 6)
die(`invalid MAC address: ${mac}`);

let b = '';

for (let x in p)
b += pack('B', int(x, 16));

return b;
}

function mac_string(data) {
if (length(data) < 6)
return '';

let b = unpack(
'>BBBBBB',
substr(data, 0, 6)
);

return sprintf(
'%02x:%02x:%02x:%02x:%02x:%02x',
b[0], b[1], b[2],
b[3], b[4], b[5]
);
}


/*
 * ------------------------------------------------------------
 * CLI
 * ------------------------------------------------------------
 */

let count = 0;
let interval = DEFAULT_INTERVAL;
let flood_interval = null;
let timeout = DEFAULT_TIMEOUT;
let quiet = false;

function usage() {
print(
`Usage: lcpping [options]

Options:
  -c COUNT       stop after COUNT requests
  -i INTERVAL    seconds between requests (default: 1)
  -if INTERVAL   flood mode; send without waiting for replies
  -W TIMEOUT     reply timeout in seconds (default: 3)
  -q             quiet
  -h             help

Without -c, lcpping runs until Ctrl+C.
`
);
}

for (let i = 0; i < length(ARGV); i++) {
let arg = ARGV[i];

if (arg == '-h' || arg == '--help') {
usage();
exit(0);
}
else if (arg == '-q') {
quiet = true;
}
else if (arg == '-c') {
if (++i >= length(ARGV))
die('-c requires an argument');

count = int(ARGV[i]);

if (count <= 0)
die('invalid count');
}
else if (arg == '-if') {
        if (++i >= length(ARGV))
                die('-if requires an argument');

        flood_interval = +ARGV[i];

        if (!(flood_interval > 0))
                die('invalid flood interval');

        if (flood_interval < 0.0007)
                die('-if minimum interval is 0.0007 seconds');
}

else if (arg == '-i') {
if (++i >= length(ARGV))
die('-i requires an argument');

interval = +ARGV[i];

if (!(interval > 0))
die('invalid interval');
}
else if (arg == '-W') {
if (++i >= length(ARGV))
die('-W requires an argument');

timeout = +ARGV[i];

if (!(timeout > 0))
die('invalid timeout');
}
else {
die(`unknown option: ${arg}`);
}
}


/*
 * ------------------------------------------------------------
 * PPPoE discovery
 * ------------------------------------------------------------
 */

function discover_pppoe() {
let data = fs.readfile('/proc/net/pppoe');

if (!data)
die('cannot read /proc/net/pppoe');

for (let line in split(data, '\n')) {
line = trim(line);

if (!line || match(line, /^Id\s+/))
continue;

let m = match(
line,
/^([0-9A-Fa-f]+)\s+([0-9A-Fa-f:]{17})\s+(\S+)/
);

if (!m)
continue;

let sid = htons16(int(m[1], 16));
let peer_mac = m[2];
let dev = m[3];

let local_mac =
fs.readfile(`/sys/class/net/${dev}/address`);

if (!local_mac)
die(`cannot determine MAC address of ${dev}`);

return {
dev: dev,
session: sid,
peer_mac: peer_mac,
local_mac: trim(local_mac)
};
}

die('no active PPPoE session found');
}


/*
 * ------------------------------------------------------------
 * Parse Ethernet + PPPoE + PPP LCP
 * ------------------------------------------------------------
 */

function parse_lcp(pkt, pppoe) {
if (pkt == null || length(pkt) < 30)
return null;

let eth = unpack(
'>6s6sH',
substr(pkt, 0, 14)
);

if (eth[2] != ETH_P_PPP_SES)
return null;

let dst = mac_string(eth[0]);
let src = mac_string(eth[1]);

let ph = unpack(
'>BBHH',
substr(pkt, 14, 6)
);

if (ph[0] != 0x11)
return null;

if (ph[1] != 0)
return null;

if (ph[2] != pppoe.session)
return null;

let proto =
unpack('>H', substr(pkt, 20, 2))[0];

if (proto != PPP_LCP)
return null;

let lh = unpack(
'>BBHI',
substr(pkt, 22, 8)
);

return {
src: src,
dst: dst,
code: lh[0],
id: lh[1],
length: lh[2],
magic: lh[3]
};
}


/*
 * ------------------------------------------------------------
 * PPPoE information
 * ------------------------------------------------------------
 */

let pppoe = discover_pppoe();


/*
 * ------------------------------------------------------------
 * Magic cache
 *
 * Format:
 *
 * 8d1a c5ab9870
 * ------------------------------------------------------------
 */

function load_cached_magic() {
let data = fs.readfile(MAGIC_CACHE);

if (!data)
return null;

let m = match(
trim(data),
/^([0-9A-Fa-f]{1,8})\s+([0-9A-Fa-f]{8})$/
);

if (!m)
return null;

let cached_sid = int(m[1], 16);
let cached_magic = int(m[2], 16);

if (cached_sid != pppoe.session)
return null;

return cached_magic;
}

function save_cached_magic(magic) {
let f = fs.open(MAGIC_CACHE, 'w');

if (!f)
return false;

f.write(
sprintf(
'%04x %08x\n',
pppoe.session,
magic
)
);

f.close();

return true;
}


/*
 * ------------------------------------------------------------
 * Fallback Magic discovery
 *
 * tcpdump watches only locally transmitted LCP packets.
 * Maximum wait: 3 seconds.
 *
 * We accept either:
 *   local Echo-Request
 *   local Echo-Reply
 *
 * Both contain our local negotiated Magic Number.
 * ------------------------------------------------------------
 */

function discover_magic() {
        const ETH_P_ALL = 0x0003;

        let cap_sock = socket.create(
                socket.AF_PACKET,
                socket.SOCK_RAW | socket.SOCK_NONBLOCK,
                htons16(ETH_P_ALL)
        );

        if (!cap_sock)
                return null;

        let deadline = now_ns() + 3000000000;

        while (now_ns() < deadline) {
                let remaining = int((deadline - now_ns()) / 1000000);

                if (remaining < 1)
                        remaining = 1;

                let events = socket.poll(
                        remaining,
                        cap_sock
                );

                if (events == null)
                        continue;

                let addr = {};

                let pkt = cap_sock.recv(
                        2048,
                        socket.MSG_DONTWAIT,
                        addr
                );

                if (pkt == null)
                        continue;

                if (addr.interface != pppoe.dev)
                        continue;

                let p = parse_lcp(pkt, pppoe);

                if (!p)
                        continue;

                if (p.src != pppoe.local_mac)
                        continue;

                if (p.dst != pppoe.peer_mac)
                        continue;

                if (p.code != LCP_ECHO_REQUEST && p.code != LCP_ECHO_REPLY)
                        continue;

                let magic = p.magic;

                cap_sock.close();
                return magic;
        }

        cap_sock.close();
        return null;
}


/*
 * ------------------------------------------------------------
 * Load / discover Magic
 * ------------------------------------------------------------
 */

let local_magic = load_cached_magic();

if (local_magic == null) {
if (!quiet)
printf(
'Detecting local LCP Magic-Number on %s... ',
pppoe.dev
);

local_magic = discover_magic();

if (local_magic == null) {
if (!quiet)
print('failed\n');

die(
'could not determine local LCP Magic-Number; ' +
'no valid cache exists for this PPPoE session'
);
}

save_cached_magic(local_magic);

if (!quiet)
printf('0x%08x\n', local_magic);
}


/*
 * ------------------------------------------------------------
 * Raw PPPoE socket
 * ------------------------------------------------------------
 */

let sock = socket.create(
socket.AF_PACKET,
socket.SOCK_RAW | socket.SOCK_NONBLOCK,
htons16(ETH_P_PPP_SES)
);

if (!sock)
die(`socket(AF_PACKET): ${socket.error()}`);

let destination = {
family: socket.AF_PACKET,
interface: pppoe.dev,
protocol: ETH_P_PPP_SES,
address: pppoe.peer_mac
};


/*
 * Ethernet header
 */

let ethernet =
mac_bytes(pppoe.peer_mac) +
mac_bytes(pppoe.local_mac) +
pack('>H', ETH_P_PPP_SES);


/*
 * ------------------------------------------------------------
 * Statistics
 * ------------------------------------------------------------
 */

let transmitted = 0;
let received = 0;

let rtt_min = null;
let rtt_max = null;
let rtt_sum = 0.0;
let rtt_sum_sq = 0.0;

let run_started = null;

let running = true;
let stop_requested = false;
let in_flight = false;


/*
 * ------------------------------------------------------------
 * Statistics output
 * ------------------------------------------------------------
 */

function print_statistics() {
let loss = 0.0;

if (transmitted > 0)
loss =
((transmitted - received) * 100.0) /
transmitted;

print('\n');

printf(
'--- %s LCP ping statistics ---\n',
pppoe.peer_mac
);

printf(
'%d packets transmitted, %d received, %.1f%% packet loss\n',
transmitted,
received,
loss
);

        if (run_started != null) {
                let elapsed =
                        ns_to_ms(
                                now_ns() - run_started
                        ) / 1000.0;

                printf(
                        'time = %.3f s\n',
                        elapsed
                );
        }

if (received > 0) {
let avg = rtt_sum / received;

let variance =
(rtt_sum_sq / received) -
(avg * avg);

if (variance < 0)
variance = 0;

let mdev = variance ** 0.5;

printf(
'rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n',
rtt_min,
avg,
rtt_max,
mdev
);
}
}


/*
 * ------------------------------------------------------------
 * Ctrl+C
 * ------------------------------------------------------------
 */

signal('INT', function() {
        if (in_flight)
                stop_requested = true;
        else
                running = false;
});


/*
 * ------------------------------------------------------------
 * Send Echo-Request
 * ------------------------------------------------------------
 */

function send_echo(identifier) {
let lcp =
pack('>H', PPP_LCP) +
pack(
'>BBHI',
LCP_ECHO_REQUEST,
identifier,
8,
local_magic
);

let pppoe_hdr =
pack(
'>BBHH',
0x11,
0x00,
pppoe.session,
length(lcp)
);

let frame =
ethernet +
pppoe_hdr +
lcp;

let n = sock.send(
frame,
0,
destination
);

if (n == null)
die(`send(): ${sock.error()}`);

return n;
}


/*
 * ------------------------------------------------------------
 * Wait Echo-Reply
 * ------------------------------------------------------------
 */

function wait_reply(identifier, timeout_ns) {
let deadline =
now_ns() + timeout_ns;

while (now_ns() < deadline) {
let remaining =
int(
(deadline - now_ns()) /
1000000
);

if (remaining < 1)
remaining = 1;

let events = socket.poll(
remaining,
sock
);

if (!running)
return null;

if (events == null)
continue;

let pkt = sock.recv(
2048,
socket.MSG_DONTWAIT
);

if (pkt == null)
continue;

let p = parse_lcp(pkt, pppoe);

if (!p)
continue;

if (p.code != LCP_ECHO_REPLY)
continue;

if (p.id != identifier)
continue;

if (p.src != pppoe.peer_mac)
continue;

if (p.dst != pppoe.local_mac)
continue;

return p;
}

return null;
}


/*
 * ------------------------------------------------------------
 * Header
 * ------------------------------------------------------------
 */

if (!quiet) {
printf(
'LCP PING %s via %s: session=0x%04x magic=0x%08x\n',
pppoe.peer_mac,
pppoe.dev,
pppoe.session,
local_magic
);
}


/*
 * ------------------------------------------------------------
 * Main loop
 * ------------------------------------------------------------
 */

run_started = now_ns();

let sequence = 1;


/*
 * ------------------------------------------------------------
 * Sequential mode (-i)
 * ------------------------------------------------------------
 */

if (flood_interval == null) {
        while (running) {
                if (count > 0 && transmitted >= count)
                        break;

                let identifier =
                        ((sequence - 1) % 255) + 1;

                let started = now_ns();

                let bytes =
                        send_echo(identifier);

                transmitted++;
                in_flight = true;

                let reply = wait_reply(
                        identifier,
                        sec_to_ns(timeout)
                );

                in_flight = false;

                if (!running)
                        break;

                if (reply) {
                        let rtt =
                                ns_to_ms(
                                        now_ns() - started
                                );

                        received++;

                        rtt_sum += rtt;
                        rtt_sum_sq += rtt * rtt;

                        if (rtt_min == null ||
                            rtt < rtt_min)
                                rtt_min = rtt;

                        if (rtt_max == null ||
                            rtt > rtt_max)
                                rtt_max = rtt;

                        if (!quiet) {
                                printf(
                                        '%d bytes from %s: lcp_seq=%d id=%d magic=0x%08x time=%.3f ms\n',
                                        bytes,
                                        pppoe.peer_mac,
                                        sequence,
                                        identifier,
                                        reply.magic,
                                        rtt
                                );
                        }
                }
                else {
                        if (!quiet) {
                                printf(
                                        'Request timeout for lcp_seq %d\n',
                                        sequence
                                );
                        }
                }

                if (stop_requested) {
                        running = false;
                        break;
                }

                sequence++;

                if (!running)
                        break;

                if (count > 0 &&
                    transmitted >= count)
                        break;

                let next_send =
                        started +
                        sec_to_ns(interval);

                while (
                        running &&
                        now_ns() < next_send
                ) {
                        let remaining =
                                int(
                                        (next_send -
                                         now_ns()) /
                                        1000000
                                );

                        if (remaining < 1)
                                remaining = 1;

                        let events =
                                socket.poll(
                                        remaining,
                                        sock
                                );

                        if (!running)
                                break;

                        if (events != null) {
                                sock.recv(
                                        2048,
                                        socket.MSG_DONTWAIT
                                );
                        }
                }
        }
}


/*
 * ------------------------------------------------------------
 * Flood mode (-if)
 *
 * Requests are transmitted according to their own clock.
 * Replies are processed independently.
 *
 * An Identifier is never reused while a request using that
 * Identifier is still outstanding.
 *
 * Since the LCP Identifier is one octet, at most 255 requests
 * may be outstanding simultaneously.
 * ------------------------------------------------------------
 */

else {
        let pending = [];
        let pending_count = 0;

        let flood_ns =
                sec_to_ns(flood_interval);

        let timeout_ns =
                sec_to_ns(timeout);

        let next_send =
                now_ns();


        /*
         * Find an unused LCP Identifier.
         */

        function get_free_identifier() {
                let preferred =
                        ((sequence - 1) % 255) + 1;

                for (let offset = 0;
                     offset < 255;
                     offset++) {

                        let id =
                                ((preferred - 1 + offset) %
                                 255) + 1;

                        if (pending[id] == null)
                                return id;
                }

                return null;
        }


        /*
         * Drain every currently queued Echo-Reply.
         */

        function receive_flood_replies() {
                while (true) {
                        let pkt =
                                sock.recv(
                                        2048,
                                        socket.MSG_DONTWAIT
                                );

                        if (pkt == null)
                                break;

                        let p =
                                parse_lcp(
                                        pkt,
                                        pppoe
                                );

                        if (!p)
                                continue;

                        if (p.code !=
                            LCP_ECHO_REPLY)
                                continue;

                        if (p.src !=
                            pppoe.peer_mac)
                                continue;

                        if (p.dst !=
                            pppoe.local_mac)
                                continue;

                        let req =
                                pending[p.id];

                        if (req == null)
                                continue;

                        let rtt =
                                ns_to_ms(
                                        now_ns() -
                                        req.sent
                                );

                        received++;

                        rtt_sum += rtt;
                        rtt_sum_sq += rtt * rtt;

                        if (rtt_min == null ||
                            rtt < rtt_min)
                                rtt_min = rtt;

                        if (rtt_max == null ||
                            rtt > rtt_max)
                                rtt_max = rtt;

                        if (!quiet) {
                                printf(
                                        '%d bytes from %s: lcp_seq=%d id=%d magic=0x%08x time=%.3f ms\n',
                                        req.bytes,
                                        pppoe.peer_mac,
                                        req.seq,
                                        p.id,
                                        p.magic,
                                        rtt
                                );
                        }

                        pending[p.id] = null;
                        pending_count--;

                        in_flight =
                                pending_count > 0;
                }
        }


        /*
         * Expire requests that exceeded -W.
         */

        function expire_flood_requests() {
                let now = now_ns();

                for (let id = 1;
                     id <= 255;
                     id++) {

                        let req =
                                pending[id];

                        if (req == null)
                                continue;

                        if ((now - req.sent) <
                            timeout_ns)
                                continue;

                        if (!quiet && !stop_requested) {
                                printf(
                                        'Request timeout for lcp_seq %d\n',
                                        req.seq
                                );
                        }

                        pending[id] = null;
                        pending_count--;
                }

                in_flight =
                        pending_count > 0;
        }


        /*
         * Main flood event loop.
         */

        while (running ||
               pending_count > 0) {

                /*
                 * Ctrl+C:
                 *
                 * stop transmitting immediately,
                 * then drain existing requests.
                 */

                if (stop_requested)
                        running = false;


                /*
                 * Receive before transmitting more.
                 */

                receive_flood_replies();
                expire_flood_requests();


                /*
                 * -c stops new transmissions but existing
                 * requests are still drained.
                 */

                if (count > 0 &&
                    transmitted >= count)
                        running = false;


                /*
                 * Send every request currently due.
                 *
                 * If the clock has advanced past multiple
                 * intervals, this loop catches up until either
                 * the schedule is current or all 255 IDs are
                 * occupied.
                 */

                let now = now_ns();

                while (
                        running &&
                        now >= next_send &&
                        pending_count < 255 &&
                        (count == 0 ||
                         transmitted < count)
                ) {
                        let identifier =
                                get_free_identifier();

                        if (identifier == null)
                                break;

                        let sent =
                                now_ns();

                        let bytes =
                                send_echo(identifier);

                        pending[identifier] = {
                                seq: sequence,
                                sent: sent,
                                bytes: bytes
                        };

                        pending_count++;
                        transmitted++;

                        in_flight = true;

                        sequence++;

                        next_send += flood_ns;

                        now = now_ns();
                }


                /*
                 * Re-check after TX.
                 */

                receive_flood_replies();
                expire_flood_requests();


                /*
                 * Nothing left after Ctrl+C / -c.
                 */

                if (!running &&
                    pending_count == 0)
                        break;


                /*
                 * Find the next event:
                 *
                 *   - next scheduled transmission
                 *   - earliest outstanding timeout
                 *
                 * socket.poll() uses milliseconds.
                 * For sub-ms deadlines it receives 0 and
                 * therefore returns immediately.
                 */

                now = now_ns();

                let wait_ns = null;

                if (running &&
                    pending_count < 255) {

                        let d =
                                next_send - now;

                        if (d < 0)
                                d = 0;

                        wait_ns = d;
                }

                for (let id = 1;
                     id <= 255;
                     id++) {

                        let req =
                                pending[id];

                        if (req == null)
                                continue;

                        let d =
                                (req.sent +
                                 timeout_ns) -
                                now;

                        if (d < 0)
                                d = 0;

                        if (wait_ns == null ||
                            d < wait_ns)
                                wait_ns = d;
                }

                if (wait_ns == null)
                        continue;

                let wait_ms =
                        int(
                                wait_ns /
                                1000000
                        );

                if (wait_ms < 0)
                        wait_ms = 0;

                socket.poll(
                        wait_ms,
                        sock
                );
        }
}


print_statistics();

sock.close();

exit(received > 0 ? 0 : 1);
