# Deep_Packet_Inspection
---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology that examines the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What My DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |


### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Four Versions

| Executable | Entry Point | Use Case |
|---------|------|----------|
| `packet_analyzer` | `src/main.cpp` | Basic packet reader and protocol parser |
| `dpi_simple` | `src/main_working.cpp` | Single-threaded DPI with blocking and reports |
| `dpi_engine` | `src/dpi_mt.cpp` | Multi-threaded DPI with LB→FP pipeline |
| `dpi_full` | `src/main_dpi.cpp` | Full engine with wildcard blocking, port blocking and rules file |
---

## 4. File Structure

```
Deep_Packet_Inspection/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
│
├── src/                        # Implementation files
│   ├── pcap_reader.cpp        # PCAP file handling
│   ├── packet_parser.cpp      # Protocol parsing (Ethernet/IP/TCP/UDP)
│   ├── sni_extractor.cpp      # TLS SNI, HTTP Host, DNS extraction
│   ├── types.cpp              # App classification (sniToAppType)
│   ├── main.cpp               # BASIC VERSION - packet reader 
│   ├── main_simple.cpp        # Minimal SNI test version
│   ├── main_working.cpp       # SIMPLE DPI - blocking + reports 
│   ├── dpi_mt.cpp             # MULTI-THREADED VERSION 
│   ├── main_dpi.cpp           # FULL ENGINE entry point 
│   ├── dpi_engine.cpp         # Full engine orchestrator
│   ├── load_balancer.cpp      # LB thread logic
│   ├── fast_path.cpp          # FP thread + TCP state machine
│   ├── connection_tracker.cpp # Flow table management
│   └── rule_manager.cpp       # Thread-safe rule engine
│
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Tracing a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```cpp
PcapReader reader;
reader.open("capture.pcap");
```


**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

### Step 3: Parse Protocol Headers

```cpp
PacketParser::parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```cpp
FiveTuple tuple;
tuple.src_ip = parseIP(parsed.src_ip);
tuple.dst_ip = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];  // Get or create
```


### Step 5: Extract SNI (Deep Packet Inspection)

```cpp
// For HTTPS traffic (port 443)
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni); // AppType::YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) 
   Byte 5: Handshake Type = 0x01 (Client Hello) 
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND
   ```

4. **Map SNI to App Type:**
   ```cpp
   // In types.cpp
   if (sni.find("youtube") != std::string::npos) {
       return AppType::YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```cpp
// Check IP blacklist
if (blocked_ips.count(src_ip)) return true;

// Check app blacklist
if (blocked_apps.count(app)) return true;

// Check domain blacklist (substring match)
for (const auto& dom : blocked_domains) {
    if (sni.find(dom) != std::string::npos) return true;
}

return false;
```

### Step 7: Forward or Drop

```cpp
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packet_header);
    output.write(packet_data);
}
```

### Step 8: Generate Report

After processing all packets:
```cpp
// Count apps
for (const auto& [tuple, flow] : flows) {
    app_stats[flow.app_type]++;
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`dpi_mt.cpp`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```cpp
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);
    
    // Hash to select Load Balancer
    size_t lb_idx = hash(pkt.tuple) % num_lbs;
    
    // Push to LB's queue
    lbs_[lb_idx]->queue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```cpp
void LoadBalancer::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Hash to select Fast Path
        size_t fp_idx = hash(pkt.tuple) % num_fps_;
        
        // Push to FP's queue
        fps_[fp_idx]->queue().push(pkt);
    }
}
```

#### Step 3: Fast Path Thread

```cpp
void FastPath::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Look up flow (each FP has its own flow table)
        Flow& flow = flows_[pkt.tuple];
        
        // Classify (SNI extraction)
        classifyFlow(pkt, flow);
        
        // Check rules
        if (rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            stats_->dropped++;
        } else {
            // Forward: push to output queue
            output_queue_->push(pkt);
        }
    }
}
```

#### Step 4: Output Writer Thread

```cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();
        
        // Write to output file
        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```cpp
template<typename T>
class TSQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();  // Wake up waiting consumer
    }
    
    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&]{ return !queue_.empty(); });
        T item = queue_.front();
        queue_.pop();
        return item;
    }
};
```

---

## 7. Deep Dive: Each Component

### pcap_reader.h / pcap_reader.cpp

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 identifies PCAP
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    uint32_t snaplen;        // Max packet size captured
    uint32_t network;        // 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp (seconds)
    uint32_t ts_usec;        // Timestamp (microseconds)
    uint32_t incl_len;       // Bytes saved in file
    uint32_t orig_len;       // Original packet size
};
```

**Key functions:**
- `open(filename)`: Open PCAP, validate header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.h / packet_parser.cpp

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```cpp
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTCP(...);       // Extract ports, flags, seq numbers
    // OR
    parseUDP(...);       // Extract ports
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Your computer might use little-endian. We use `ntohs()` and `ntohl()` to convert:
```cpp
// ntohs = Network TO Host Short (16-bit)
uint16_t port = ntohs(*(uint16_t*)(data + offset));

// ntohl = Network TO Host Long (32-bit)
uint32_t seq = ntohl(*(uint32_t*)(data + offset));
```

### sni_extractor.h / sni_extractor.cpp

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, 
    size_t length
) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```cpp
std::optional<std::string> HTTPHostExtractor::extract(
    const uint8_t* payload,
    size_t length
) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### types.h / types.cpp

**Purpose:** Define data structures used throughout

**FiveTuple:**
```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    
    bool operator==(const FiveTuple& other) const;
};
```

**AppType:**
```cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // ... more apps
};
```

**sniToAppType function:**
```cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos) 
        return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) 
        return AppType::FACEBOOK;
    // ... more patterns
}
```

---

## 8. Working of SNI

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, size_t length
) {
    // Check TLS record header
    if (payload[0] != 0x16) return std::nullopt;  // Not handshake
    if (payload[5] != 0x01) return std::nullopt;  // Not Client Hello
    
    size_t offset = 43;  // Skip to session ID
    
    // Skip Session ID
    uint8_t session_len = payload[offset];
    offset += 1 + session_len;
    
    // Skip Cipher Suites
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;
    
    // Skip Compression Methods
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;
    
    // Read Extensions Length
    uint16_t ext_len = readUint16BE(payload + offset);
    offset += 2;
    
    // Search for SNI extension
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_data_len = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (ext_type == 0x0000) {  // SNI!
            // Parse SNI structure
            uint16_t sni_len = readUint16BE(payload + offset + 3);
            return std::string(
                (char*)(payload + offset + 5), 
                sni_len
            );
        }
        
        offset += ext_data_len;
    }
    
    return std::nullopt;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```


---

## 10. Building and Running

### Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| C++ Compiler | g++ 7+ or clang++ 5+ | Compiles the C++17 source code |
| CMake | 3.16+ | Cross-platform build system |
| — | — | No external libraries needed! |



### Build
 
**Windows:**
```bash
mkdir build                      # create a separate folder for compiled files (keeps source code clean)
cd build                         # move into the build folder
cmake .. -G "MinGW Makefiles"    # read CMakeLists.txt and generate Windows-compatible build files
mingw32-make                     # compile all source files and link the 4 executables
```
 
**Linux / macOS:**
```bash
mkdir build                      # create a separate folder for compiled files (keeps source code clean)
cd build                         # move into the build folder
cmake ..                         # read CMakeLists.txt and generate build files
make                             # compile all source files and link the 4 executables
```
  

This compiles all source files and links **4 executables**

---



### Run the Executables

> **Windows users:** Run this first for proper output display:
> ```cmd
> chcp 65001
> ```

---

#### Executable 1: `packet_analyzer` — Basic Packet Reader

Reads a PCAP file and prints every packet's protocol details — MAC, IP, ports, TCP flags, payload preview.

```bash
# Windows
packet_analyzer.exe test_dpi.pcap           # read and print all packets
packet_analyzer.exe test_dpi.pcap 10        # stop after first 10 packets

# macOS/Linux
./packet_analyzer test_dpi.pcap             # read and print all packets
./packet_analyzer test_dpi.pcap 10          # stop after first 10 packets
```

**What you'll see:**
```
========== Packet #1 ==========
Time: 2024-01-15 10:23:45.123456

[Ethernet]
  Source MAC:      00:11:22:33:44:55
  Destination MAC: aa:bb:cc:dd:ee:ff
  EtherType:       0x0800 (IPv4)

[IPv4]
  Source IP:      192.168.1.100
  Destination IP: 142.250.185.110
  Protocol:       TCP
  TTL:            64

[TCP]
  Source Port:      54321
  Destination Port: 443
  Flags:            SYN
```

---

#### Executable 2: `dpi_simple` — Single-Threaded DPI Engine

Reads packets, classifies traffic by app (YouTube, TikTok, etc.) using SNI extraction, applies blocking rules, writes filtered output to a new PCAP file, and prints a full report.

```bash
# Windows
dpi_simple.exe test_dpi.pcap output.pcap                                                                          # analyze only, no blocking
dpi_simple.exe test_dpi.pcap output.pcap --block-app YouTube                                                      # block all YouTube traffic
dpi_simple.exe test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok                                   # block multiple apps at once
dpi_simple.exe test_dpi.pcap output.pcap --block-ip 192.168.1.50                                                  # block all traffic from this IP
dpi_simple.exe test_dpi.pcap output.pcap --block-domain facebook                                                  # block any domain containing "facebook"
dpi_simple.exe test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok --block-ip 192.168.1.50 --block-domain facebook  # combine all rules

# macOS/Linux
./dpi_simple test_dpi.pcap output.pcap                                                                            # analyze only, no blocking
./dpi_simple test_dpi.pcap output.pcap --block-app YouTube                                                        # block all YouTube traffic
./dpi_simple test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok                                     # block multiple apps at once
./dpi_simple test_dpi.pcap output.pcap --block-ip 192.168.1.50                                                    # block all traffic from this IP
./dpi_simple test_dpi.pcap output.pcap --block-domain facebook                                                    # block any domain containing "facebook"
./dpi_simple test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok --block-ip 192.168.1.50 --block-domain facebook    # combine all rules
```

**What you'll see:**
```
[BLOCKED] 192.168.1.100 -> 142.250.185.110 (YouTube: www.youtube.com)
[BLOCKED] 192.168.1.100 -> 157.240.1.35 (Facebook: www.facebook.com)

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:              77                             ║
║ Forwarded:                  74                             ║
║ Dropped:                     3                             ║
║ Active Flows:               43                             ║
╠══════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                     ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########            ║
║ Unknown              16  20.8% ####                  ║
║ YouTube               1   1.3%                       ║
╚══════════════════════════════════════════════════════════════╝

[Detected Applications/Domains]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.tiktok.com -> TikTok
```

---

#### Executable 3: `dpi_engine` — Multi-Threaded DPI Engine

Same as `dpi_simple` but runs on multiple threads in parallel using a Load Balancer → Fast Path architecture. Use `--lbs` to set Load Balancer thread count and `--fps` to set Fast Path threads per LB.

```bash
# Windows
dpi_engine.exe test_dpi.pcap output.pcap                                                            # run with default threads (2 LBs x 2 FPs = 4 threads)
dpi_engine.exe test_dpi.pcap output.pcap --lbs 2 --fps 2                                            # explicitly set 2 LB threads x 2 FP threads
dpi_engine.exe test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok --lbs 2 --fps 2    # block apps with 4 threads
dpi_engine.exe test_dpi.pcap output.pcap --lbs 4 --fps 4                                            # high throughput: 4 LBs x 4 FPs = 16 threads total

# macOS/Linux
./dpi_engine test_dpi.pcap output.pcap                                                              # run with default threads (2 LBs x 2 FPs = 4 threads)
./dpi_engine test_dpi.pcap output.pcap --lbs 2 --fps 2                                              # explicitly set 2 LB threads x 2 FP threads
./dpi_engine test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok --lbs 2 --fps 2      # block apps with 4 threads
./dpi_engine test_dpi.pcap output.pcap --lbs 4 --fps 4                                              # high throughput: 4 LBs x 4 FPs = 16 threads total
```

**Additional output shows thread statistics:**
```
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                           ║
║   LB1 dispatched:             24                           ║
║   FP0 processed:              53                           ║
║   FP1 processed:               0                           ║
║   FP2 processed:               0                           ║
║   FP3 processed:              24                           ║
```

---

#### Executable 4: `dpi_full` — Full Production DPI Engine

The most complete version. Adds wildcard domain blocking, port blocking, and the ability to save/load blocking rules from a file.

```bash
# Windows
dpi_full.exe test_dpi.pcap output.pcap --block-domain *.tiktok.com                                                               # wildcard block — blocks www.tiktok.com, api.tiktok.com, cdn.tiktok.com etc.
dpi_full.exe test_dpi.pcap output.pcap --block-port 443                                                                           # block all HTTPS traffic on port 443
dpi_full.exe test_dpi.pcap output.pcap --rules my_rules.txt                                                                       # load all blocking rules from a text file
dpi_full.exe test_dpi.pcap output.pcap --block-app YouTube --block-domain *.tiktok.com --block-ip 192.168.1.50 --lbs 2 --fps 2  # combine all rule types with 4 threads
dpi_full.exe test_dpi.pcap output.pcap --block-app YouTube --verbose                                                              # print every packet decision to screen

# macOS/Linux
./dpi_full test_dpi.pcap output.pcap --block-domain *.tiktok.com                                                                  # wildcard block — blocks www.tiktok.com, api.tiktok.com, cdn.tiktok.com etc.
./dpi_full test_dpi.pcap output.pcap --block-port 443                                                                             # block all HTTPS traffic on port 443
./dpi_full test_dpi.pcap output.pcap --rules my_rules.txt                                                                         # load all blocking rules from a text file
./dpi_full test_dpi.pcap output.pcap --block-app YouTube --block-domain *.tiktok.com --block-ip 192.168.1.50 --lbs 2 --fps 2    # combine all rule types with 4 threads
./dpi_full test_dpi.pcap output.pcap --block-app YouTube --verbose                                                                # print every packet decision to screen
```

**Rules file format** (`my_rules.txt`):
```
[BLOCKED_IPS]
192.168.1.50
10.0.0.100

[BLOCKED_APPS]
YouTube
TikTok

[BLOCKED_DOMAINS]
*.facebook.com
*.instagram.com

[BLOCKED_PORTS]
443
```

---

### Supported Blocking Options

| Option | Available In | Example | What it blocks |
|--------|-------------|---------|----------------|
| `--block-ip` | all versions | `--block-ip 192.168.1.50` | All traffic from that source IP |
| `--block-app` | all versions | `--block-app YouTube` | All connections to that app |
| `--block-domain` | all versions | `--block-domain facebook` | Any SNI containing "facebook" |
| `--block-domain` | `dpi_full` only | `--block-domain *.tiktok.com` | All TikTok subdomains (wildcard) |
| `--block-port` | `dpi_full` only | `--block-port 443` | All traffic on that port |
| `--rules` | `dpi_full` only | `--rules rules.txt` | Load rules from file |
| `--lbs` | `dpi_engine`, `dpi_full` | `--lbs 2` | Number of Load Balancer threads |
| `--fps` | `dpi_engine`, `dpi_full` | `--fps 2` | Fast Path threads per LB |
| `--verbose` | `dpi_full` only | `--verbose` | Print every packet decision |

### Supported Apps for Blocking

```
Google    YouTube    Facebook    Instagram    Twitter/X
Netflix   Amazon     Microsoft   Apple        WhatsApp
Telegram  TikTok     Spotify     Zoom         Discord
GitHub    Cloudflare
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---


## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Built With

- **C++17** — core language
- **CMake** — cross-platform build system
- **POSIX Threads** — multi-threading
- **No external libraries** — all protocol parsing implemented from scratch
