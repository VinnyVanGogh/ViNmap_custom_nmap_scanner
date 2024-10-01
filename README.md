# ViNmap

![ViNmap Logo](https://raw.githubusercontent.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/refs/heads/main/images/logo_option2.webp)


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Python 3.13 with Disabled GIL](#python-313-with-disabled-gil)
  - [Virtual Environment](#virtual-environment)
  - [Install Dependencies](#install-dependencies)
- [Usage](#usage)
  - [Basic Scan](#basic-scan)
  - [Advanced Scan](#advanced-scan)
- [Configuration](#configuration)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Introduction
**PLEASE run with sudo or as root to avoid permission issues, it will NOT copy to ~/NMAP folder if you do not run as root or with sudo since zenmap requires root priviledges**


**ViNmap** is a powerful, multithreaded Nmap scanner designed to enhance your network scanning experience. Built with Python 3.13, ViNmap leverages concurrent processing to execute multiple scans in parallel, significantly reducing the time required to analyze large IP ranges. Additionally, it offers robust XML merging capabilities, ensuring that your scan results are consolidated into a single, comprehensive report.

To achieve true multithreading performance, ViNmap utilizes a Python build with the Global Interpreter Lock (GIL) disabled, enabling real concurrent execution of threads. This setup drastically speeds up scans, making ViNmap an efficient tool for network administrators, security professionals, and enthusiasts.

Additionally allows conversion to html or json from the merged xml file.

## Features

- **Real Multithreading:** Utilizes a Python 3.13 build with the GIL disabled, allowing true multithreading and significantly speeding up scans.
- **Customizable Scan Options:** Tailor your scans with additional Nmap flags to suit your specific requirements.
- **XML Merging:** Automatically merge multiple XML scan results into a single, unified report.
- **Graceful Shutdown:** Handles interrupt signals (e.g., `Ctrl+C`) gracefully, ensuring that active scans are terminated properly without data loss.
- **Dynamic Filename Handling:** Generates unique filenames for merged results to prevent accidental overwriting.
- **Error Handling:** Robust mechanisms to handle scan failures, XML parsing issues, and file cleanup errors without halting the entire scanning process.
- **Flexible IP Range Parsing:** Supports CIDR notation and dash-separated IP ranges for versatile scanning targets.
- **Output Formatting:** Choose between XML and HTML, XML and JSON, or just XML for the final scan report.

## Prerequisites

Before installing ViNmap, ensure that you have the following prerequisites:

- **Python 3.13:** ViNmap is built and tested with Python 3.13. Ensure you have this version installed.
- **Nmap:** ViNmap relies on Nmap for network scanning. Install it using the instructions below based on your operating system.
- **Python with Disabled GIL:** For real multithreading capabilities, it's recommended to use a Python build with the Global Interpreter Lock (GIL) disabled.

## Installation

Follow these steps to set up ViNmap on your system:

### 1. Clone the Repository

```bash
git clone https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner.git
cd ViNmap_custom_nmap_scanner
```

### 2. Install Nmap

#### **macOS (Using Homebrew):**

```bash
brew install nmap
```

#### **Linux (Debian/Ubuntu):**

```bash
sudo apt-get update
sudo apt-get install nmap
```

#### **Windows:**

Download and install Nmap from the [official Nmap website](https://nmap.org/download.html).

### 3. Set Up Python 3.13 with Disabled GIL

ViNmap requires a Python 3.13 build with the Global Interpreter Lock (GIL) disabled to achieve real multithreading performance. Follow these steps to set it up:

#### **a. Download Python 3.13 Source Code**

```bash
wget https://www.python.org/ftp/python/3.13.0/Python-3.13.0rc2.tar.xz
tar -xf Python-3.13.0rc2.tar.xz
cd Python-3.13.0rc2
```

#### **b. Modify the Source to Disable GIL**

Disabling the GIL involves modifying Python's source code, which is an advanced and experimental process. Proceed with caution:

1. **Configure the GIL:**

    ```bash
    ./configure --disable-gil
    ```

2. **Configure the Build:**

   ```bash
   ./configure --prefix=/usr/local/python-3.13-no-gil
   ```

3. **Build and Install Python:**

   ```bash
   make -j$(nproc)
   sudo make install
   # or you can do `make altinstall` to avoid overwriting the system Python 
   # sudo make altinstall
   ```

#### **c. Verify the Python Build**

Ensure that your custom Python build is correctly installed:

```bash
check_python=$(which python3.13)
$check_python --version
```

### 4. Create a Virtual Environment

Create a virtual environment using the custom Python build:

```bash
check_python=$(which python3.13)
$check_python -m venv venv 
```

### 5. Activate the Virtual Environment

- **macOS/Linux:**

  ```bash
  source venv/bin/activate
  ```

- **Windows:**

  ```bash
  venv\Scripts\activate
  ```

### 6. Upgrade Pip

Ensure you have the latest version of pip:

```bash
pip install --upgrade pip
```

### 7. Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

ViNmap is designed to be user-friendly and flexible. Below are some examples to help you get started.

```bash
pip3.13 install .
# or 
pip install .
```

### Basic Scan

Perform a basic scan on a single IP or an IP range.

```bash
vinmap -ip 192.168.1.0/24
```

### Advanced Scan with Custom Options

Execute a scan with additional Nmap flags, specify the number of chunks, threads, and output file.

```bash
vinmap -ip 192.168.1.0/24 -n 4 -t 4 -s "-sV -O" -o final_scan.xml
```

#### **Parameters:**

- `-ip` or `--ip_range`: **(Required)** The IP range or subnet to scan.
- `-n` or `--num_chunks`: **(Optional)** Number of chunks to split the IP range into (default: half of the CPU cores).
- `-t` or `--threads`: **(Optional)** Number of concurrent threads (default: half of the CPU cores).
- `-s` or `--scan_type`: **(Optional)** Additional Nmap scan options (e.g., `-sV -O` for version and OS detection).
- `-o` or `--output`: **(Optional)** Final output XML file name (default: `nmap_<ip_range>_merged.xml`).
- `-f` or `--format`: **(Optional)** Output format (`html`, `json` or `xml`; default: `xml`). **does not delete the xml file after conversion to html or json**

## Configuration

ViNmap allows you to customize various aspects of the scanning process. You can modify the script or use command-line arguments to tailor scans according to your needs.

### Example Configuration

```bash
python vinmap.py -ip 10.0.0.0/16 -n 8 -t 8 -s "-sV -O --script vuln" -o comprehensive_scan.xml
```

This command scans the `10.0.0.0/16` subnet, splitting the scan into 8 chunks and using 8 threads. It includes version detection, OS detection, and runs vulnerability scripts, saving the merged XML to `comprehensive_scan.xml`.

### Screenshots

The following screenshots showcase the ViNmap interface and the merged XML report generated after a scan and opened in Zenmap:

![Zenmap Preview](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/images/zenmap_preview.png?raw=true)

## Contributing

Contributions are welcome! If you'd like to enhance ViNmap, follow these steps:

1. **Fork the Repository**

   Click the "Fork" button at the top-right corner of the repository page to create your own copy.

2. **Clone Your Fork**

   ```bash
   git clone https://github.com/your_username/ViNmap_custom_nmap_scanner.git
   cd ViNmap_custom_nmap_scanner
   ```

3. **Create a New Branch**

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Your Changes**

   Implement your feature or fix a bug.

5. **Commit Your Changes**

   ```bash
   git commit -m "Add feature: your feature description"
   ```

6. **Push to Your Fork**

   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**

   Navigate to the original repository and click "Compare & pull request" to submit your changes.

## License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute it as per the terms of the license.

## Contact

For any inquiries or support, please reach out to:

- **Author:** Vince Vasile
- **Email:** [vince@example.com](mailto:vince@example.com)
- **GitHub:** [VinnyVanGogh](https://github.com/VinnyVanGogh)

---

## Additional Notes

- **Caution:** Disabling the GIL is an advanced modification and may lead to instability. It is recommended only for users who are comfortable with building Python from source and handling potential issues.
- **Performance Benefits:** With the GIL disabled, ViNmap can execute multiple threads truly concurrently, significantly speeding up scans, especially when dealing with large IP ranges.
- **Alternative Solutions:** If modifying the GIL is not feasible, consider using process-based concurrency (e.g., `multiprocessing`) to achieve parallelism.

---

### **Explanation of the Updates:**

1. **Python 3.13 Compatibility:**
   - Added to the **Prerequisites** section to specify the required Python version.
   - Updated the **Installation** section to guide users on setting up Python 3.13.

2. **Disabled GIL for Real Multithreading:**
   - Introduced in both the **Features** and **Prerequisites** sections.
   - Detailed instructions in the **Installation** section under **Python 3.13 with Disabled GIL**.
   - Emphasized the performance benefits in the **Additional Notes** section.

3. **Emphasis on Speed Improvements:**
   - Highlighted how disabling the GIL drastically speeds up scans in the **Features** and **Additional Notes** sections.

4. **Cautionary Notes:**
   - Added warnings about the complexity and potential instability when disabling the GIL to inform users of the risks involved.

