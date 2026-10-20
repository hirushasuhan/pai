# RFC 9021: Distributed Consensus Protocol Specification

## 1. Abstract
This specification defines the Paxos and Raft hybrid model designed for high-availability partitioned datastores. It establishes strict guarantees on linearizability, bounded leader election times, and quorum intersection.

## 2. Protocol Invariants
* **State Machine Safety**: If any server has applied a particular log entry at a given index to its state machine, no other server will ever apply a different log entry for the same index.
* **Leader Append-Only**: A leader never overwrites or truncates its own log entries; it only appends new entries.
* **Log Matching Property**: If two logs contain an entry with the same index and term, then the logs are identical in all entries up through the given index.

## 3. Quorum Intersection
For cluster size $N = 2F + 1$, any two quorums $Q_1$ and $Q_2$ must overlap by at least one server:
$$|Q_1 \cap Q_2| \ge 1$$

## 4. Message Formats
| Field | Type | Description |
| :--- | :--- | :--- |
| `term` | `uint64` | Current leader election epoch |
| `candidate_id` | `uuid` | Candidate requesting vote |
| `last_log_index` | `uint64` | Index of candidate's last log entry |
| `last_log_term` | `uint64` | Term of candidate's last log entry |
