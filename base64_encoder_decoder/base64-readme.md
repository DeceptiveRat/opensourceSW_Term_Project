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