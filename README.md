# Customized Intrusion Detection System (IDS)

This project implements a basic custom Intrusion Detection System (IDS) using Python and Scapy. The IDS captures network traffic and applies signature-based detection to identify potential attacks like SYN floods and port scans.

## Features
- Packet capture using `scapy`
- Signature-based detection for common attacks
- Supports both incoming and outgoing traffic analysis
- Filters traffic based on your device's IP address

## Requirements
- Python 3.x
- Scapy

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/custom-ids.git
    ```
2. Navigate into the project directory:
    ```bash
    cd custom-ids
    ```
3. Create a virtual environment and activate it:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```
4. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1. Replace the `my_ip` variable in the Python script (`ids.py`) with your device's IP address.
   
2. Run the IDS script:
    ```bash
    sudo python3 ids.py
    ```
    *Note: Running as root (using `sudo`) is required to capture network packets.*

3. The script will capture packets involving your device and detect any suspicious activity based on the attack signatures defined.

## Attack Signatures Detected:
- SYN flood
- Port scan
- Other customizable signatures

## Future Work
- Add support for anomaly-based detection
- Improve visualization for traffic analysis
- Support distributed IDS

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
