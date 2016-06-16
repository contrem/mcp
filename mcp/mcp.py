import uuid
import time
import struct
import select
import socket
import random
import logging
from collections import namedtuple, Counter

log = logging.getLogger('mcp')

# Log to console.
console = logging.StreamHandler()
fmt = '%(asctime)s [%(levelname)s] (%(module)s): %(message)s'
formatter = logging.Formatter(fmt)
console.setFormatter(formatter)
console.setLevel(logging.DEBUG)
log.setLevel(logging.CRITICAL)

if not log.handlers:
    log.addHandler(console)

# 224.0.0.0-255 lan multi-cast
# 224.0.0.1 == all hosts on local segment
# ff02::1 == all hosts on local segment

PORT = 7767

PKT_FMT = struct.Struct('<BBBBI16B')
PKT = namedtuple('MCP_PKT', 'type major minor padding term uuid')
EVT = namedtuple('MCP_EVT', 'type term uuid')

MSG_VOTE = ord(b'V')
MSG_REQUEST = ord(b'R')
MSG_HEARTBEAT = ord(b'H')

TICK = ord(b'T')
FOLLOWER = ord(b'F')
CANDIDATE = ord(b'C')
MASTER = ord(b'M')

TERM_MASK = 0xffffffff

class CTX():
    def __init__(self):
        self.host = None
        self.target = None
        self.port = None
        self.term = None
        self.state = None
        self.uuid = None
        self.master = None
        self.nodes = None
        self.heartbeat = None
        self.et_low = None
        self.et_high = None
        self.et_range = None
        self.election_timeout = None
        self._sock = None

    @property
    def sock(self):
        if self._sock is None:
            self._sock = create_socket(self.host, self.port)

        return self._sock

    @property
    def majority(self):
        nodes = self.nodes
        if callable(nodes): nodes = nodes()
        return abs(nodes) // 2 + 1

def create_socket(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setblocking(0)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((addr, port))
    return s

def logger():
    return logging.getLogger('mcp')

def parse_message(message):
    t, major, minor, _, term, *uuid_bytes = PKT_FMT.unpack_from(message)
    uid = uuid.UUID(bytes=bytes(uuid_bytes))
    return PKT._make((t, 0, 0, 0, term, uid))

def create_message(t, term, uid):
    return PKT._make((t, 0, 0, 0, term, uid))

def pack_message(msg):
    term = msg.term & TERM_MASK
    return PKT_FMT.pack(msg.type, msg.major, msg.minor, msg.padding, term,
                        *msg.uuid.bytes)

def next_election_timeout(et_low, et_high):
    return random.randint(et_low, et_high) / 1000

def send_message(ctx, msg_type, address):
    msg = create_message(msg_type, ctx.term, ctx.uuid)
    ctx.sock.sendto(pack_message(msg), address)

def recv_message(ctx):
    message, address = ctx.sock.recvfrom(PKT_FMT.size)
    if not message or len(message) < PKT_FMT.size: return (None, address)
    return parse_message(message), address

def next_term(term):
    return (term + 1) & TERM_MASK

def follow(ctx):
    et_low, et_high = ctx.et_range

    if ctx.master:
        log.info('%s: term %d: following: %s',
                 str(ctx.uuid), ctx.term, str(ctx.master))

    while True:
        if not select.select([ctx.sock], [], [], ctx.election_timeout)[0]:
            yield CANDIDATE
            return

        message, address = recv_message(ctx)
        if not message: continue

        # heartbeat or vote request
        if message.type == MSG_HEARTBEAT:
            # heartbeat
            if ctx.master != message.uuid:
                log.info('%s: term %d joining master %s %s',
                         str(ctx.uuid), message.term, str(message.uuid),
                         address)
            ctx.election_timeout = next_election_timeout(et_low, et_high)
            ctx.term = message.term
            ctx.master = message.uuid

        if message.type == MSG_REQUEST:
            # vote request
            log.info('%s: term %d election request from %s',
                     str(ctx.uuid), message.term, str(message.uuid))
            if message.term >= next_term(ctx.term):
                ctx.election_timeout = next_election_timeout(et_low, et_high)
                ctx.term = message.term
                send_message(ctx, MSG_VOTE, address)
                log.info('%s: term %d voted for %s',
                         str(ctx.uuid), message.term, str(message.uuid))

        yield TICK

    yield FOLLOWER

def campaign(ctx):
    ctx.term = next_term(ctx.term)
    et_low, et_high = ctx.et_range
    ctx.election_timeout = next_election_timeout(et_low, et_high)

    log.info('%s: term %d election starting', str(ctx.uuid), ctx.term)

    votes = Counter({ctx.uuid.bytes : 1})
    send_message(ctx, MSG_REQUEST, (ctx.target, ctx.port))

    duration = 0.0
    start = time.time()
    majority = ctx.majority
    while True:

        log.debug('%s; election: duration %fs/%fs',
                  str(ctx.uuid), duration, ctx.election_timeout)

        if select.select([ctx.sock], [], [], ctx.heartbeat)[0]:
            message, address = recv_message(ctx)
            if not message: continue

            if message.type == MSG_VOTE:
                log.info('%s: vote from %s term %d',
                         str(ctx.uuid), str(message.uuid), message.term)
                votes[message.uuid.bytes] += 1

        log.debug('%s: term %d votes %d/%d',
                  str(ctx.uuid), ctx.term, sum(votes.values()), majority)

        tally = sum(votes.values())
        if tally >= majority:
            # won election
            log.info('%s: term %d election won %d/%d',
                     str(ctx.uuid), ctx.term, tally, majority)
            yield MASTER
            return

        duration = time.time() - start
        if duration > ctx.election_timeout:
            log.info('%s: term %d election failed: %d/%d votes',
                      str(ctx.uuid), ctx.term, sum(votes.values()), majority)
            break

        yield TICK

    yield FOLLOWER

def lead(ctx):
    # become master
    log.info('%s: becoming master term %d', str(ctx.uuid), ctx.term)
    ctx.master = ctx.uuid

    while True:
        # send heartbeat
        start = time.time()
        send_message(ctx, MSG_HEARTBEAT, (ctx.target, ctx.port))

        if select.select([ctx.sock], [], [], ctx.heartbeat)[0]:

            message, address = recv_message(ctx)
            if not message: continue

            if message.type == MSG_HEARTBEAT and message.uuid != ctx.uuid:
                # heartbeat - another master up
                if message.term > ctx.term:
                    # no longer the master
                    ctx.term = message.term
                    ctx.master = message.uuid
                    break

        delay = ctx.heartbeat / 1.5 - (time.time() - start)
        if delay > 0:
            time.sleep(delay)

        yield TICK

    yield FOLLOWER

def tick(ctx):
    log.debug('%s: tick: state %s term %d', str(ctx.uuid), ctx.state, ctx.term)
    yield ctx.state

def events(host, port, **kwargs):
    broadcast = True
    kwargs.setdefault('nodes', 2)
    kwargs.setdefault('heartbeat', 10)
    kwargs.setdefault('timeout_range', (150, 300))

    ctx = CTX()

    ctx.host = host if not broadcast else ''
    ctx.target = host if host else '<broadcast>'
    ctx.port = port if port else PORT
    ctx.term = term = 0
    ctx.state = state = FOLLOWER
    ctx.uuid = uid = uuid.uuid4()
    ctx.nodes = nodes = abs(kwargs.get('nodes'))
    ctx.heartbeat = heartbeat = kwargs.get('heartbeat') / 1000
    ctx.et_range = kwargs.get('timeout_range')
    ctx.et_low, ctx.et_high = ctx.et_range
    ctx.election_timeout = et = next_election_timeout(ctx.et_low, ctx.et_high)

    log.info('%s: et: %s -> %fs hb: %fs %s/%s:%d',
             ctx.uuid, str(ctx.et_range), ctx.election_timeout, heartbeat,
             host, ctx.target, port)

    transitions = {
        FOLLOWER : follow,
        CANDIDATE : campaign,
        MASTER : lead,
        TICK : tick,
    }

    while True:
        for state in transitions[ctx.state](ctx):
            if state != TICK: ctx.state = state
            yield EVT(type = state, term = ctx.term, uuid = ctx.uuid)

def loop(host, port, **kwargs):
    nop = lambda u, e: u
    on_follower = kwargs.get('on_follower', nop)
    on_candidate = kwargs.get('on_candidate', nop)
    on_master = kwargs.get('on_master', nop)
    on_tick = kwargs.get('on_tick', nop)
    user_data = kwargs.get('user_data', None)

    for event in events(host, port, **kwargs):
        et = event.type
        if et == FOLLOWER:
            on_follower(user_data, event)
        if et == CANDIDATE:
            on_candidate(user_data, event)
        if et == MASTER:
            on_master(user_data, event)
        if et == TICK:
            on_tick(user_data, event)

if __name__ == '__main__':
    logger().setLevel(logging.INFO)
    loop('', PORT)
