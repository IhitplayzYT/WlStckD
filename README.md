# WlStckD - Stateful WiFi Firewall Kernel Module

A Linux kernel module that implements a stateful packet filtering firewall with connection tracking and heuristic-based attack detection. Designed for WiFi devices to provide gateway-level packet filtering.

## Features

### Stateful Connection Tracking
- Tracks TCP, UDP, and ICMP connections using a hash table
- Maintains connection state (NEW, ESTABLISHED, RELATED, INVALID)
- Validates TCP state transitions to prevent protocol violations
- Automatic cleanup of stale connections (5-minute timeout)

### Heuristic-Based Attack Detection
- **SYN Flood Protection**: Blocks IPs sending more than 100 SYN packets per second
- **Port Scan Detection**: Blocks IPs scanning more than 10 different ports per second
- **Invalid State Blocking**: Drops packets with invalid TCP state transitions

### Statistics and Monitoring
- Real-time packet statistics via `/proc/wlstckd_stats`
- Tracks total, allowed, and blocked packets
- Breakdown of blocks by attack type (SYN flood, port scan, invalid state)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Netfilter Hook                           │
│                  (NF_INET_PRE_ROUTING)                       │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│                   Packet Processing                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   TCP       │  │   UDP       │  │   ICMP      │        │
│  │ Processing  │  │ Processing  │  │ Processing  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Heuristic Detection Layer                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ SYN Flood    │  │ Port Scan    │  │ State        │      │
│  │ Detection    │  │ Detection    │  │ Validation   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│              Connection State Table                         │
│           (1024-bucket hash table with RCU)                  │
└─────────────────────────────────────────────────────────────┘
```

## Building

```bash
# Clean previous builds
make clean

# Build the module
make
```

This will produce `WlStckD.ko` kernel module.

## Installation

```bash
# Load the module (requires root)
sudo insmod WlStckD.ko

# Verify module is loaded
lsmod | grep WlStckD

# Check kernel logs for initialization message
dmesg | tail
```

## Usage

### Viewing Statistics

```bash
# View real-time firewall statistics
cat /proc/wlstckd_stats
```

Output example:
```
WlStckD Firewall Statistics
=========================
Total packets:      123456
Allowed packets:    120000
Blocked packets:    3456
SYN flood blocked:  123
Port scan blocked:  456
Invalid state blocked: 78
```

### Unloading the Module

```bash
# Remove the module (requires root)
sudo rmmod WlStckD

# Check kernel logs for final statistics
dmesg | tail
```

## Configuration

The firewall uses hardcoded thresholds defined in `include/WlStckD.h`:

- `SYN_RATE_THRESHOLD`: 100 SYN packets per second
- `PORT_SCAN_THRESHOLD`: 10 different ports per second
- `CONN_HASH_SIZE`: 1024 hash buckets
- Connection timeout: 300 seconds (5 minutes)
- Tracker timeout: 60 seconds (1 minute)

To modify these thresholds, edit the header file and rebuild the module.

## Security Considerations

- The module hooks into the Netfilter PRE_ROUTING chain, processing all incoming IPv4 packets
- Only TCP, UDP, and ICMP packets are tracked; other protocols are allowed by default
- The module uses spinlocks for thread-safe access to connection tables
- RCU (Read-Copy-Update) is used for connection entry cleanup to minimize performance impact

## Performance

- Hash table lookup: O(1) average case
- Minimal packet processing overhead
- Periodic cleanup runs every 60 seconds
- Memory usage scales with number of active connections

## Testing

To test the firewall:

```bash
# Load the module
sudo insmod WlStckD.ko

# Generate some traffic (e.g., ping, curl)
ping -c 5 8.8.8.8
curl https://example.com

# Check statistics
cat /proc/wlstckd_stats

# Unload when done
sudo rmmod WlStckD
```

## Troubleshooting

### Module fails to load
Check kernel logs: `dmesg | tail`
Common issues:
- Kernel headers not installed
- Incompatible kernel version
- Missing dependencies

### No packets being filtered
- Verify the module is loaded: `lsmod | grep WlStckD`
- Check Netfilter hook registration in kernel logs
- Ensure you're processing IPv4 traffic (module only handles IPv4)

### High memory usage
- Connection table may have many entries
- Consider reducing `CONN_HASH_SIZE` or connection timeout
- Monitor with: `cat /proc/wlstckd_stats`

## License

GPL - See LICENSE file for details.

## Author

Ihit

## Version

1.0
