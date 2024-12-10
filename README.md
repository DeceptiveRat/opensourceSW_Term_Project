# 1. Packet sniffer
## 1-1 Description
On unswitched networks, Ethernet packets pass through every device on the network. This means any device can pick up packets that aren't meant for itself. This is called packet sniffing. This program allows you to do just that. 
Currently, it can capture packets, verify the checksum of UDP and TCP packets, and save them to a file. More features, such as identifying DNS traffic are being added.

## 1-2 Installation
git clone the repository into your desktop environment and you are good to go!
(Note: originally developed for Linux Operating Systems. Probably will not work in Windows environments)

## 1-3 Usage
navigate to the "packet_sniffer" directory and 
```bash 
sudo ./decode_sniff
```
to start the program. 

![Image display failed](packet_sniffer/chooseInterface.png?raw=true)\
Choose the interface you want to use.

![Image display failed](packet_sniffer/successMessage.png?raw=true)\
If it worked properly, you should get the success message like the picture.

![Image display failed](packet_sniffer/result.png?raw=true)\
![Image display failed](packet_sniffer/packet.png?raw=true)\
If you open the new txt file, the packets that have been caught are displayed there.

## 1-4 License 
This project is licensed under the GNU General Public License v3. See the [LICENSE](packet_sniffer/LICENSE) file for details.

## 1-5 Acknowledgements
This project was inspired by concepts and examples presented in *Hacking: The Art of Exploitation (2nd Edition, 2008)* by Jon Erickson. 

## 2. OTHER PROJECTS GO HERE

# Base64 Encoder/Decoder GUI Application

## Overview

This is a simple, user-friendly GUI application built with Python and Tkinter that allows users to easily encode and decode text using Base64 encoding.

## Features

- Encode text to Base64
- Decode Base64 encoded text
- Copy result to clipboard

## Prerequisites

### System Requirements
- Python 3.7 or higher
- Tkinter library (usually comes pre-installed with Python)

### Required Libraries
- `tkinter` (standard library)
- `base64` (standard library)

## Installation

### Option 1: Direct Python Script
1. Ensure Python is installed on your system
2. Save the script as `base64_gui.py`
3. Run directly using Python

```bash
python base64_gui.py
```

### Option 2: Virtual Environment (Recommended)
```bash
# Create a virtual environment
python -m venv base64_env

# Activate the virtual environment
# On Windows
base64_env\Scripts\activate
# On macOS/Linux
source base64_env/bin/activate

# Run the script
python base64_gui.py
```

## Usage Instructions

1. Launch the application
2. Input your text in the top text area
   - For encoding: Enter plain text
   - For decoding: Enter Base64 encoded text
3. Click appropriate button:
   - "Encode to Base64" converts plain text to Base64
   - "Decode from Base64" converts Base64 back to plain text
4. Result appears in the bottom text area
5. Use "Copy Result" to copy output to clipboard

### Example Scenarios

#### Encoding
- Input: `Hello, World!`
- Click "Encode to Base64"
- Result: `SGVsbG8sIFdvcmxkIQ==`

#### Decoding
- Input: `SGVsbG8sIFdvcmxkIQ==`
- Click "Decode from Base64"
- Result: `Hello, World!`

## Troubleshooting

- **Tkinter Not Installed**: Reinstall Python, ensuring Tkinter is included
- **Encoding Errors**: Ensure input is valid UTF-8 text
- **Decoding Errors**: Verify Base64 string is correctly formatted

## License

This project is licensed under MIT License.


# 3. Chrome Dino with Open CV

## 3-1 Description
Simple bot that can automatically play the Chrome Dinosaur Game using OpenCV for computer vision. The bot will identify obstacles and control the game dynamically by simulating key presses.

## 3-2 Installation

## 3-3 Run

## 3-4 License 

## 3-5 Acknowledgements
