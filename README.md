# frida-sslkeylog

**This version is designed to hook processes where OpenSSL has 
been linked statically into the executable (or library). Before using the script you 
have to edit the module name and the function addresses in `agent.js`.** 

Frida tool to dump an [NSS Key
Log](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
for Wireshark, from a process using dynamically linked OpenSSL (or BoringSSL).

```
CLIENT_RANDOM <64 hex characters of client random data> <96 hex characters of master key>
```

## Installation

Install the dependencies (`frida-tools` and `pyasn1`).

```sh
pip3 install -r requirements.txt
```

## Usage

 1. If necessary, start [Frida server](https://www.frida.re/docs/android/) on
    your Android device

    While this should work elsewhere, it was written for and only tested on Android.

 2. Run the Frida tool. For example, to connect to an Android device over USB

    ```bash
    ./sslkeylog -U -n <package name> -o <key log filename>
    ```

    As the key log file is opened in append mode, you can run multiple
    instances of the tool at the same time.

    **Chromium-based browsers will not work because they statically link
    BoringSSL. Firefox-based browsers will not work because they use NSS.**

 3. Set the "(Pre-)Master-Secret log filename" in the protocol configuration
    for SSL, in Wireshark. Wireshark should display a tab named "Decrypted SSL
    Data" for subsequent packets from the processes.
