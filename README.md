# Master Consensus Protocol
-------------------------------------------------------------------------------
Broadcast voting protocol based on RAFT.

Two import values:

*heartbeat*
: Time in milliseconds between heartbeat messages

*election-timeout*
: Time in milliseconds before starting a new election

Example:
```
virtualenv -p python3 env
source env/bin/activate
python setup install

# failover example optionally runs a command when transitioning between Follower and Master
./examples/failover --help

# on two nodes run
./examples/failover --nodes 2 --verbose --up echo --down echo
```
