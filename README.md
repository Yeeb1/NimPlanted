# NimPlanted

A Python script to recover the AES key and decrypt traffic between the [NimPlant](https://github.com/chvancooten/NimPlant) C2 server and the implants by exploiting the limited keyspace of the XOR key used in pre-crypto operations. It basically leverages the limited keyspace of the XOR key used during the initial AES key exchange, making it feasible to brute-force and  AES key recovery.

<p align="center">
  <img src="https://github.com/user-attachments/assets/794f888c-6882-4839-9080-7e0ea306725e" width="300">
</p>

## Background

### XOR Key Generation in NimPlant

The NimPlant C2 server generates the XOR key using the function [get_xor_key](https://github.com/chvancooten/NimPlant/blob/fd17dfb5728562eb380a89dc61dca99026369d66/nimplant.py#L52):

```python
def get_xor_key(force_new=False):
    """Get the XOR key for pre-crypto operations."""
    if os.path.isfile(".xorkey") and not force_new:
        file = open(".xorkey", "r", encoding="utf-8")
        xor_key = int(file.read())
    else:
        print("Generating unique XOR key for pre-crypto operations...")
        print(
            "NOTE: Make sure the '.xorkey' file matches if you run the server elsewhere!"
        )
        xor_key = random.randint(0, 2147483647)
        with open(".xorkey", "w", encoding="utf-8") as file:
            file.write(str(xor_key))

    return xor_key
```

- **Keyspace**: The XOR key is a 31-bit integer, ranging from `0` to `2,147,483,647` (`2^31 - 1`).
- **Usage**: This XOR key is used to obfuscate the AES key before it is sent to the agent.

### Agent Registration and Key Exchange

When the agent checks in with the server, it receives the XORed AES key.

**Agent Registration Request:**

```http
GET /register HTTP/1.1
Connection: Keep-Alive
Accept: */*
Accept-Encoding: gzip
User-Agent: NimPlant C2 Client
Host: <C2 Server IP>
```

**Server Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 49
Server: NimPlant C2 Server
Date: Thu, 31 Oct 2024 07:53:14 GMT

{"id":"F7RRpl1Q","k":"Hxp+byQ2MxQOHS0+bWoSPQ=="}
```

- **`k` Field**: Contains the base64-encoded, XOR-obfuscated AES key.


## How It Works

1. **XOR Key Brute-Forcing**:
   - The XOR key is a 31-bit integer, making brute-forcing feasible.
   - The script iterates over all possible XOR key values (`0` to `2^31 - 1`).

2. **AES Key De-obfuscation**:
   - For each XOR key candidate, the script reverses the obfuscation to obtain an AES key candidate.

3. **AES Key Validation**:
   - Checks if the AES key candidate is valid (16 alphanumeric characters).

4. **Decryption Attempt**:
   - Uses the AES key candidate to decrypt the provided encrypted data.
   - Validates the decrypted data by checking if it is printable, valid JSON, or zlib-compressed.

5. **Caching**:
   - Upon successful recovery, the AES key is cached for future use.

6. **Traffic Decryption**:
   - The recovered AES key is used to decrypt agent traffic, handling JSON responses, base64-encoded fields, and compressed data.

## Usage

The script operates in two modes: `recover` and `decrypt`.

### General Syntax

```bash
python3 NimPlanted.py [--cache_file CACHE_FILE] [--debug] {recover,decrypt} [options]

usage: NimPlanted.py [-h] [--cache_file CACHE_FILE] [--debug] {recover,decrypt} ...

AES Key Recovery and Decryption Script

positional arguments:
  {recover,decrypt}     Modes of operation
    recover             Recover the AES key exchanged during NimPlant agent check-in
    decrypt             Decrypt the data

options:
  -h, --help            show this help message and exit
  --cache_file CACHE_FILE, -c CACHE_FILE
                        Path to a cache of a recovered AES key
  --debug, -d           Enable debug mode for detailed output
```

- `--cache_file`: Specify a custom cache file for the AES key (default: `aes_key.cache`).
- `--debug`: Enable debug mode for detailed output.

### Recover Mode

Brute-force the XOR key to recover the AES key.


```bash
python3 NimPlanted.py recover --xored_key <XORed_Key_Base64> --enc_file <Encrypted_File>

usage: NimPlanted.py recover [-h] --xored_key XORED_KEY --enc_file ENC_FILE

options:
  -h, --help            show this help message and exit
  --xored_key XORED_KEY, -k XORED_KEY
                        Base64 encoded XORed AES key (k-Variable)
  --enc_file ENC_FILE, -f ENC_FILE
                        Path to a file containing base64-encoded encrypted data (Ideally a short t- or data-
                        Variable)
```


### Decrypt Mode

Decrypt encrypted agent traffic using the AES key.


```bash
python3 NimPlanted.py decrypt --enc_file <Encrypted_File> [--aes_key <AES_Key>] [--xored_key <XORed_Key_Base64>] [--output_file <Output_File>]

usage: NimPlanted.py decrypt [-h] --enc_file ENC_FILE [--aes_key AES_KEY] [--xored_key XORED_KEY]
                             [--output_file OUTPUT_FILE]

options:
  -h, --help            show this help message and exit
  --enc_file ENC_FILE, -f ENC_FILE
                        Path to a file containing base64-encoded encrypted data
  --aes_key AES_KEY, -a AES_KEY
                        AES key for decryption (if not provided, key recovery will be attempted)
  --xored_key XORED_KEY, -k XORED_KEY
                        Base64 encoded XORed AES key (k-Variable) (if no AES key or cached key is available,
                        recovery will be started automatically)
  --output_file OUTPUT_FILE, -o OUTPUT_FILE
                        Output file for binary data when decrypted content is not JSON
```


- If `--aes_key` is provided, it uses this key for decryption and overwrites any cached key.
- If no `--aes_key` is provided, it tries to use the cached key.
- If no cached key is available, it attempts to recover the AES key using the provided `--xored_key`.

## Examples

### Recovering the AES Key


```bash
python3 NimPlanted.py recover -k 'Hxp+byQ2MxQOHS0+bWoSPQ==' -f data.b64

[+] Recovered AES Key: 15RBvecEXJyk71Jd
[+] Cached AES Key to 'aes_key.cache'.
```

### Decrypting Agent Traffic


```bash
python3 NimPlanted.py decrypt -f data2.64
```

#### Handling Encrypted JSON with Base64-Encoded 'result' Field


```bash
python3 NimPlanted.py decrypt -f data2.b64

[+] Using cached AES Key from 'aes_key.cache'.
[+] Decrypted Content (JSON):
 {
    "i": "10.13.37.10",
    "u": "commando",
    "h": "COMMANDO",
    "o": "Windows 10 build 19045",
    "p": 548,
    "P": "NimPlant.exe",
    "r": true
}
[-] 'result' field not found in JSON data.
```

#### Decrypting and Decompressing Binary Data

If the decrypted content is binary and zlib-compressed:


```bash
python3 NimPlanted.py decrypt -f data3.b64


[+] Using cached AES Key from 'aes_key.cache'.
[+] Decrypted data is zlib-compressed. Decompressed successfully.
[+] Decompressed binary data saved to 'decompressed_output.bin'.
```

