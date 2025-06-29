# Ransomware Detection Patterns - Detailed Analysis

## What is This?

This project is a prototype AI-based tool for detecting ransomware using static and behavioral features from executable files.

> **Note:** This project is for educational and research purposes only.

## How to Use

1. Install requirements: `pip install -r requirements.txt`
2. Run the app: `streamlit run app.py`
3. Upload your CSV file for prediction.

## Disclaimer

This tool is a prototype and may not be 100% accurate. Do not use for real-world security decisions.

## Overview

The ransomware detection model uses a **Random Forest classifier** trained on 21,752 samples (50% malware, 50% benign) with **99% accuracy**. Here are the key patterns it identifies:

## 🎯 Primary Detection Patterns

### 1. **Behavioral Indicators (Most Important - 86.2% of total importance)**

#### **Malicious Process Activity** (34.65% importance)

- **Pattern**: Number of malicious processes spawned
- **Malware average**: 3.62 processes
- **Benign average**: 0.02 processes
- **Key insight**: Ransomware typically spawns multiple malicious processes for encryption, communication, and persistence

#### **File System Manipulation** (16.37% importance)

- **Malicious files created**: 16.48 vs 0.25 (benign)
- **Unknown file types**: 57.86 vs 0.20 (benign)
- **Suspicious files**: Higher activity in malware samples
- **Key insight**: Ransomware creates numerous encrypted files and backup deletion tools

#### **Registry Activity** (13.48% importance)

- **Total registry operations**: 3,784.85 vs 768.11 (benign)
- **Registry reads**: Significantly higher in malware
- **Key insight**: Ransomware heavily modifies registry for persistence, disabling security tools, and system configuration changes

#### **Process Monitoring** (5.56% importance)

- **Monitored processes**: 13.82 vs 2.73 (benign)
- **Key insight**: Ransomware monitors system processes to avoid detection and target specific applications

#### **Network Activity** (6.51% importance)

- **DNS queries**: Higher frequency in malware
- **HTTP connections**: Increased network communication
- **Key insight**: Ransomware communicates with C&C servers for key exchange and payment instructions

### 2. **PE File Structure Patterns** (4.1% of total importance)

#### **Memory Layout Characteristics**

- `rdata_VirtualAddress` and `rdata_VirtualSize`: Read-only data section properties
- `SizeOfImage`: Total memory footprint
- `EntryPoint`: Code execution starting point
- **Key insight**: Ransomware often has specific memory layouts for packing/obfuscation

#### **Code Section Properties**

- `SizeOfCode`: Size of executable code
- `text_VirtualSize`: Text section size
- **Key insight**: Packed or encrypted ransomware has unusual code section ratios

## 🦠 Ransomware Families Detected

The model successfully identifies 25+ ransomware families including:

### **Major Families** (by sample count):

1. **Phobos** (550 samples)
2. **Snake** (527 samples)
3. **NanoCore** (520 samples)
4. **Raccoon** (518 samples)
5. **Remcos** (512 samples)
6. **njRat** (506 samples)
7. **Dharma** (505 samples)
8. **WannaCry** (497 samples)
9. **Ryuk** (449 samples)
10. **LockBit** (438 samples)

### **Notable Ransomware-as-a-Service (RaaS)**:

- **REvil** (347 samples)
- **Gandcrab** (382 samples)
- **DarkSide** (335 samples)
- **Maze** (290 samples)

## 🔍 Detection Methodology

### **Feature Categories**:

1. **Dynamic Analysis Features** (86.2% weight)

   - Process behavior monitoring
   - File system operations
   - Registry modifications
   - Network communications

2. **Static Analysis Features** (13.8% weight)
   - PE header properties
   - Section characteristics
   - Import table analysis
   - File metadata

### **Key Discriminators**:

- **Malicious processes**: 180x higher in ransomware
- **File manipulation**: 65x more malicious files created
- **Registry activity**: 5x higher registry operations
- **Unknown files**: 289x more unknown file types

## 🛡️ Implications for Defense

### **High-Priority Monitoring**:

1. **Process spawning patterns** - Monitor for rapid process creation
2. **File system changes** - Watch for mass file modifications/encryptions
3. **Registry modifications** - Alert on security-related registry changes
4. **Network communications** - Monitor C&C traffic patterns

### **Early Warning Signs**:

- Sudden increase in registry operations
- Multiple unknown processes spawning
- Unusual network DNS/HTTP activity
- Mass file system operations

This model effectively combines behavioral analysis with static file analysis to achieve high accuracy in ransomware detection, with behavioral indicators being the strongest predictors of malicious intent.
