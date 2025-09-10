.
# StegoTool

A versatile and secure Python-based steganography application designed to hide files and messages inside images. Choose between two powerful methods (**LSB** via `stegano` or **Steghide**) and add an optional layer of **AES encryption** for maximum security.

## Features

-   **Hide Data**: Embed secret text messages or entire files within common image formats (PNG, BMP, JPG).
-   **Dual Methods**: Utilize either the common **LSB (Least Significant Bit)** method or the robust **Steghide** tool for data embedding.
-   **Military-Grade Encryption**: Optionally encrypt your payload with **AES-256** using a user-provided password before hiding it.
-   **Extract Data**: Reveal and decrypt hidden data from images with the correct password.
-   **User-Friendly CLI**: A simple command-line interface makes the tool easy to use.

## How It Works

1.  **Embedding**:
    -   You provide an input image, a secret message/file, and an optional password.
    -   The tool encrypts the data (if a password is given) using AES-256.
    -   The encrypted data is then hidden inside the image using your chosen method (LSB or Steghide).
    -   A new, seemingly identical output image is created, containing your secret.

2.  **Extracting**:
    -   You provide the stego image and the same password used during embedding (if encrypted).
    -   The tool extracts the hidden data from the image.
    -   If encrypted, it decrypts the data using the password to reveal the original secret message or file.

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/your-username/StegoTool.git
    cd StegoTool
    ```

2.  **Create a Virtual Environment (Recommended)**:
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
    *Alternatively, install manually:*
    ```bash
    pip install stegano cryptography pillow
    # Also ensure 'steghide' is installed on your system:
    # sudo apt-get install steghide  # For Kali/Debian/Ubuntu
    ```

## Usage

Run the tool from the command line:
```bash
python stegotool.py
