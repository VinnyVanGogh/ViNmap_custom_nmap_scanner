# ViNmap

![ViNmap Logo](https://raw.githubusercontent.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/refs/heads/main/.github/images/logo.webp)


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
    - [Optional Prerequisites for enhanced performance:](#optional-prerequisites-for-enhanced-performance)
- [Configuration](#configuration)
    - [Example Configuration](#example-configuration)
- [Installation](#installation)
    - [Install Nmap](#install-nmap)
        - [macOS (Using Homebrew):](#macos-using-homebrew)
        - [Linux (Debian/Ubuntu):](#linux-debianubuntu)
        - [Windows:](#windows)
    - [Install ViNmap](#install-vinmap)
        - [Verify the Installation](#verify-the-installation)
    - [To Install ViNmap in an editable mode:](#to-install-vinmap-in-an-editable-mode)
        - [Clone the Repository or Create a Fork to Contribute](#clone-the-repository-or-create-a-fork-to-contribute)
        - [Create a Virtual Environment](#create-a-virtual-environment)
        - [Activate the Virtual Environment](#activate-the-virtual-environment)
        - [Upgrade Pip](#upgrade-pip)
        - [Install Dependencies](#install-dependencies)
        - [Install ViNmap in Editable mode](#install-vinmap-in-editable-mode)
- [Usage](#usage)
    - [Command-Line Arguments](#command-line-arguments)
    - [Parameters:](#parameters)
        - [Examples:](#examples)
            - [Basic Scan](#basic-scan)
            - [Basic Scan with custom output path and html or json format](#basic-scan-with-custom-output-path-and-html-or-json-format)
            - [Advanced Scan with Custom Options](#advanced-scan-with-custom-options)
            - [List scan options](#list-scan-options)
- [Optional Python 3.13 Beta (Advanced)](#optional-python-313-beta)
  - [About Setting up Python 3.13 with GIL disabled](#about-setting-up-python-313-with-disabled-gil)
    - [Download and Extract Python 3.13 Beta](#download-and-extract-python-313-beta)
    - [Modify the Source and Configure the Build](#modify-the-source-and-configure-the-build)
      - [Configure the GIL:](#configure-the-gil)
      - [Configure the Build:](#configure-the-build)
    - [Build and Install Python](#build-and-install-python)
    - [Update the `PATH` Environment Variable (Optional)](#update-the-path-environment-variable-optional)
    - [Verify the Python Build and Run ViNmap with Python 3.13](#verify-the-python-build-and-run-vinmap-with-python-313)
    - [Run ViNmap with python3.13](#run-vinmap-with-python313)
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

- **Minimum Python Version:** Python 3.6 or higher is required to run ViNmap.
- **Nmap:** ViNmap relies on Nmap for network scanning. Install it using the instructions below based on your operating system.

### Optional Prerequisites for enhanced performance:

- **Python 3.13:** ViNmap is built and tested with Python 3.13. This version is fully optional, but allows disabling the GIL, enabling true multithreading performance. You can use the latest stable Python version if you prefer not to disable the GIL. You can read more about Python 3.13 [here](#about-setting-up-python-313-with-disabled-gil).
- **Python with Disabled GIL:** For real multithreading capabilities, it's recommended to use a Python build with the Global Interpreter Lock (GIL) disabled.

## Configuration

ViNmap allows you to customize various aspects of the scanning process. You can modify the script or use command-line arguments to tailor scans according to your needs.

### Example Configuration

```bash
python vinmap.py -ip 10.0.0.0/16 -n 8 -t 8 -s "-sV -O --script vuln" -o comprehensive_scan.xml
```

This command scans the `10.0.0.0/16` subnet, splitting the scan into 8 chunks and using 8 threads. It includes version detection, OS detection, and runs vulnerability scripts, saving the merged XML to `comprehensive_scan.xml`.

## Installation

Follow these steps to set up ViNmap on your system:

### 1. Install Nmap

##### **macOS (Using Homebrew):**

```bash
brew install nmap
```

##### **Linux (Debian/Ubuntu):**

```bash
sudo apt-get update
sudo apt-get install nmap
```

##### **Windows:**

Download and install Nmap from the [official Nmap website](https://nmap.org/download.html).

### 2. Install ViNmap 

```bash
pip install --upgrade pip
pip install vinmap
```

#### 3. Verify the Installation

Check if ViNmap is installed correctly with pip, which will show the package details such as version, location, and dependencies:

```bash
pip show vinmap
```

Check if the `vinmap` command is available in your terminal and show the help message:

```bash
vinmap --help
```

## To Install ViNmap in an editable mode:

#### Clone the Repository or Create a Fork to Contribute

**A. Clone the ViNmap repository to your local machine:**

```bash
git clone https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner.git
cd ViNmap_custom_nmap_scanner
```

**B. Fork the repository and clone your fork:**

```bash
gh repo fork VinnyVanGogh/ViNmap_custom_nmap_scanner
cd ViNmap_custom_nmap_scanner
```

#### Create a Virtual Environment

Create a virtual environment to isolate the dependencies:

```bash
python -m venv venv
```

#### Activate the Virtual Environment

Activate the virtual environment based on your operating system:

- **macOS/Linux:**

  ```bash
  source venv/bin/activate
  ```

- **Windows:**

  ```bash
  venv\Scripts\activate
  ```

#### Upgrade Pip

Ensure you have the latest version of pip:

```bash
pip install --upgrade pip
```

#### Install Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```

#### Install ViNmap in Editable mode

Make sure you are in the root directory of the cloned repository and run the following command:
**This will install the package in editable mode, allowing you to make changes to the code and see the changes reflected immediately.**

```bash
pip install -e .
```

## Usage

ViNmap is designed to be user-friendly and flexible. Below are some examples to help you get started.

The easiest way to install is to use pip, and download the latest stable release from pypi.

```bash
pip install vinmap
```

Alternatively, you can clone the repository and install it locally [here](#to-install-vinmap-in-an-editable-mode).

### Command-Line Arguments 

ViNmap supports various command-line arguments to customize your scans. Here are the available options:

```bash
vinmap -ip <ip_range> [-n <num_chunks>] [-t <threads>] [-s <scan_type>] [-l] [-o <path/to/output>] [-f <format>]
```

### **Parameters:**

- `-ip` or `--ip_range`: **(Required)** The IP range or subnet to scan.
- `-n` or `--num_chunks`: **(Optional)** Number of chunks to split the IP range into (default: half of the CPU cores).
- `-t` or `--threads`: **(Optional)** Number of concurrent threads (default: half of the CPU cores).
- `-s` or `--scan_type`: **(Optional)** Additional Nmap scan options (e.g., `-sV -O` for version and OS detection).
- `-l` or `--list_scan_types`: **(Optional)** List available scan types, can be ran with or without `-s` \ `--scan_type` argument, and will combine with the `-s` \ `--scan_type` if ran together.
- `-o` or `--output`: **(Optional)** Final output XML file name (default: `nmap_<ip_range>_merged.xml`).
- `-f` or `--format`: **(Optional)** Output format (`html`, `json` or `xml`; default: `xml`). **does not delete the xml file after conversion to html or json**

### Examples:

Below are some examples of how to use ViNmap with different command-line arguments.

#### Basic Scan

Perform a basic scan on a single IP or an IP range.

```bash
vinmap -ip/--ip_range scanme.nmap.org
```

#### Basic Scan with custom output path and html or json format

Perform a basic scan on a single IP or an IP range and specify the output file and format.

**This still saves an XML file, but also converts it to html or json**
  - The json or html file will be saved in the same directory as the xml file, and with the same base name as the xml file.

```bash 
vinmap -ip/--ip_range 10.0.0.0/24 -o/--output custom_output.xml -f/--format html
```

#### Advanced Scan with Custom Options

Execute a scan with additional Nmap flags, specify the number of chunks, threads, and output file. 
  - Default chunks and threads are half of the CPU cores, and default output file is nmap_<ip_range>_merged.xml

```bash
vinmap -ip 192.168.1.0/24 -n/--num_chunks 8 -t/--threads 8 -s/--scan_type "-sV -O --script vuln" -o/--output comprehensive_scan.xml
```

#### List scan options

List scan options and select a number to use that as a scan type. 
  - Can be ran with or without -s argument and will combine with the -s/--scan_type argument if ran together

```bash 
vinmap --list_scan_types -s/--scan_type "-sV -O --script vuln "
```

or

```bash 
vinmap --list_scan_types
```

## Optional Python 3.13 Beta 

**ViNmap is optimized for Python 3.13, which is currently in beta. To use the latest features and enhancements, you can set up Python 3.13 on your system.**

### About setting up Python 3.13 with Disabled GIL

#### **WARNING:** Disabling the Global Interpreter Lock (GIL) can lead to instability and unexpected behavior in Python. Use this feature at your own risk.

ViNmap requires a Python 3.13 build with the Global Interpreter Lock (GIL) disabled to achieve real multithreading performance. Follow these steps to set it up:

**Note:** These instructions are for advanced users who are comfortable with building Python from source and modifying the GIL settings.

### Download and Extract Python 3.13 Beta

```bash
wget https://www.python.org/ftp/python/3.13.0/Python-3.13.0rc2.tar.xz
tar -xf Python-3.13.0rc2.tar.xz
cd Python-3.13.0rc2
```

### Modify the Source and Configure the Build


#### Configure the GIL:

```bash
./configure --disable-gil
```

#### Configure the Build:

```bash
./configure --prefix=/usr/local/python-3.13-no-gil
```

### Build and Install Python

```bash
make -j$(nproc)
sudo make install
# or you can do `make altinstall` to avoid overwriting the system Python 
# sudo make altinstall
```

### Update the `PATH` Environment Variable (Optional)

**Update the `PATH` Environment Variable if you want to use the new Python installation by default.**

Add the new Python installation to your `PATH`:

```bash
export PATH=/usr/local/python-3.13-no-gil/bin:$PATH
```

### Verify the Python Build and Run ViNmap with Python 3.13

**Verify the Python Build and Installation:**

Ensure that your custom Python build is correctly installed:

```bash
check_python=$(which python3.13)
$check_python --version
```

### Run ViNmap with python3.13

```bash
python3.13 vinmap.py --help
```

### Screenshots

**Example Terminal Output:**

- **Basic Scan ran with default options:**
![Basic Scan Output](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/basic_output_example.png?raw=true)

- **Aggressive Scan ran with --format html:**
![HTML Output](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/html_output_example.png?raw=true)

- **Basic Scan ran with --format json:**
![JSON Output](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/json_output_example.png?raw=true)

- **OS Detection Scan ran with default options:**
![OS Detection Output](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/os_output_example.png?raw=true)

- **List Scan Types ran with scan types as an argument:**
![List Scan Types Output](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/list_output_example.png?raw=true)

The following screenshots showcase the Zenmap interface and the merged XML report generated by ViNmap.

![Zenmap Preview](https://github.com/VinnyVanGogh/ViNmap_custom_nmap_scanner/blob/main/.github/images/zenmap_preview.png?raw=true)

## Contributing

Contributions are welcome! If you'd like to enhance ViNmap, follow these steps:

1. **Fork the Repository**

Click the "Fork" button at the top-right corner of the repository page to create your own copy or use the following command to create a fork:

**If you use GitHub CLI you can skip step 2.**

```bash
gh repo fork VinnyVanGogh/ViNmap_custom_nmap_scanner
```

2. **Clone Your Fork**

```bash
git clone https://github.com/your_username/ViNmap_custom_nmap_scanner.git
```

3. cd into the cloned repository

```bash
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

