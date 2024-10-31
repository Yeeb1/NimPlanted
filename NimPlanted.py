import argparse
import base64
import json
import string
import ast
import sys
import os
import zlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description='AES Key Recovery and Decryption Script')
    parser.add_argument('--cache_file','-c',  default='aes_key.cache', help='Path to a cache of a recovered AES key')
    parser.add_argument('--debug','-d',  action='store_true', help='Enable debug mode for detailed output')
    subparsers = parser.add_subparsers(dest='mode', help='Modes of operation')

    # Recover mode
    parser_recover = subparsers.add_parser('recover', help='Recover the AES key exchanged during NimPlant agent check-in')
    parser_recover.add_argument('--xored_key', '-k', required=True, help='Base64 encoded XORed AES key (k-Variable)')
    parser_recover.add_argument('--enc_file', '-f', required=True, help='Path to a file containing base64-encoded encrypted data (Ideally a short t- or data-Variable)')

    # Decrypt mode
    parser_decrypt = subparsers.add_parser('decrypt', help='Decrypt the data')
    parser_decrypt.add_argument('--enc_file','-f', required=True, help='Path to a file containing base64-encoded encrypted data')
    parser_decrypt.add_argument('--aes_key','-a', required=False, help='AES key for decryption (if not provided, key recovery will be attempted)')
    parser_decrypt.add_argument('--xored_key','-k', required=False, help='Base64 encoded XORed AES key (k-Variable) (if no AES key or cached key is available, recovery will be started automatically)')
    parser_decrypt.add_argument('--output_file','-o', required=False, help='Output file for binary data when decrypted content is not JSON')

    args = parser.parse_args()
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    return args


def reverse_xor_obfuscation(data: bytes, key_int: int) -> bytes:
    """Reverses the custom XOR obfuscation applied to the AES key.""" 
    result = bytearray(data) # https://github.com/chvancooten/NimPlant/blob/787014b382eae5fa46f9d4a1b5dea5009147e7ce/server/util/crypto.py#L8
    k = key_int
    for i in range(len(result)):
        for shift in [0, 8, 16, 24]:
            result[i] ^= ((k >> shift) & 0xFF)
        k = (k + 1) & 0xFFFFFFFF
    return bytes(result)


def aes_ctr_decrypt(key: bytes, encrypted_data: bytes) -> bytes:
    """Decrypts the encrypted data using AES in CTR mode."""
    iv, enc = encrypted_data[:16], encrypted_data[16:]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    try:
        decrypted_data = cipher.decrypt(enc)
        return decrypted_data
    except ValueError:
        return None


def recover_aes_key(xored_key: bytes, encrypted_data: bytes, debug: bool = False) -> bytes:
    """Attempts to recover the AES key by brute-forcing the obfuscation."""
    for key_int in range(2 ** 31):  # 2^31 possibilities

        # Reverse the XOR obfuscation
        key_candidate = reverse_xor_obfuscation(xored_key, key_int)

        # Validate the key_candidate
        try:
            decoded_str = key_candidate.decode('utf-8')
            if len(decoded_str) != 16 or not all(c in string.ascii_letters + string.digits for c in decoded_str):
                if debug and key_int % 1000000 == 0:
                    print(f"Debug: Key int {key_int}, invalid key_candidate '{key_candidate}'")
                continue  # Invalid key skip 
        except UnicodeDecodeError:
            if debug and key_int % 1000000 == 0:
                print(f"Debug: Key int {key_int}, key_candidate is not valid UTF-8")
            continue  # Invalid UTF-8 encoding skip

        if debug:
            print(f"Debug: Key int {key_int}, valid key_candidate '{decoded_str}'")

        # attempt data decryption
        decrypted_data = aes_ctr_decrypt(key_candidate, encrypted_data)
        if decrypted_data is not None:
            try:
                text = decrypted_data.decode('utf-8')
                if text.isprintable():
                    if debug:
                        print(f"Debug: Successful decryption with key '{decoded_str}'")
                    return key_candidate 
                else:
                    if debug:
                        print(f"Debug: Decrypted data is not printable with key '{decoded_str}'")
            except UnicodeDecodeError:
                if debug:
                    print(f"Debug: Decrypted data is not valid UTF-8 with key '{decoded_str}'")
                continue  # if decrypted data is not valid UTF-8 continue
        else:
            if debug:
                print(f"Debug: Decryption failed with key '{decoded_str}'")
    print("[-] No valid key found after brute-force.")
    return None


def read_encrypted_data(enc_file: str) -> bytes:
    """Reads and decodes the encrypted data from a file."""
    try:
        with open(enc_file, 'rb') as f:
            enc_data_base64 = f.read()
        encrypted_data = base64.decodebytes(enc_data_base64)
        return encrypted_data
    except Exception as e:
        print(f"[-] Error reading encrypted data: {e}")
        sys.exit(1)


def load_cached_key(cache_file: str) -> bytes:
    """Loads the AES key from the cache file if it exists."""
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cached_key_str = f.read()
            if len(cached_key_str) != 16:
                print("[-] Cached AES key is invalid length.")
                sys.exit(1)
            print(f"[+] Using cached AES Key from '{cache_file}'.")
            return cached_key_str.encode('utf-8')
        except Exception as e:
            print(f"[-] Error reading cache file: {e}")
            sys.exit(1)
    else:
        return None


def save_cached_key(cache_file: str, key_str: str):
    """Saves the AES key to the cache file."""
    try:
        with open(cache_file, 'w') as f:
            f.write(key_str)
        print(f"[+] Cached AES Key to '{cache_file}'.")
    except Exception as e:
        print(f"[-] Error writing to cache file: {e}")


def handle_recover_mode(args):
    """Handles the 'recover' mode of the script."""
    try:
        xored_aes_key = base64.b64decode(args.xored_key)
    except base64.binascii.Error as e:
        print(f"[-] Error decoding xored_key: {e}")
        sys.exit(1)

    encrypted_data = read_encrypted_data(args.enc_file)

    recovered_aes_key = recover_aes_key(xored_aes_key, encrypted_data, debug=args.debug)
    if recovered_aes_key:
        key_str = recovered_aes_key.decode('utf-8')
        print("[+] Recovered AES Key:", key_str)
        # Cache key
        save_cached_key(args.cache_file, key_str)
    else:
        print("[-] Failed to recover AES Key.")


def handle_decrypt_mode(args):
    """Handles the 'decrypt' mode of the script."""
    encrypted_data = read_encrypted_data(args.enc_file)
    aes_key = None

    if args.aes_key:
        aes_key = args.aes_key.encode('utf-8')
        if len(aes_key) != 16:
            print("[-] Provided AES key must be 16 characters long.")
            sys.exit(1)
        save_cached_key(args.cache_file, args.aes_key)
        print(f"[+] Overwritten cached AES Key with provided key in '{args.cache_file}'.")
    else:
        aes_key = load_cached_key(args.cache_file)
        if not aes_key:
            if args.xored_key:
                try:
                    xored_aes_key = base64.b64decode(args.xored_key)
                except base64.binascii.Error as e:
                    print(f"[-] Error decoding xored_key: {e}")
                    sys.exit(1)
                print("[*] No cached AES Key found. Attempting to recover the key.")
                recovered_aes_key = recover_aes_key(xored_aes_key, encrypted_data, debug=args.debug)
                if recovered_aes_key:
                    key_str = recovered_aes_key.decode('utf-8')
                    print("[+] Recovered AES Key:", key_str)
                    aes_key = recovered_aes_key
                    save_cached_key(args.cache_file, key_str) # Cache key
                else:
                    print("[-] Failed to recover AES Key.")
                    sys.exit(1)
            else:
                print("[-] No AES key provided, no cached key found, and no XORed key provided for recovery.")
                print("[-] Please provide an AES key via --aes_key, or provide --xored_key for key recovery.")
                sys.exit(1)

    decrypted_data = aes_ctr_decrypt(aes_key, encrypted_data)
    if decrypted_data:
        try:
            text = decrypted_data.decode('utf-8')
            try:
                json_data = json.loads(text)
                print("[+] Decrypted Content (JSON):\n", json.dumps(json_data, indent=4))
                if 'result' in json_data:
                    try:
                        decoded_result = base64.b64decode(json_data['result']).decode('utf-8')
                        print("[+] Decoded 'result' field:\n", decoded_result)
                    except Exception as e:
                        print(f"[-] Error decoding 'result' field: {e}")
                else:
                    print("[-] 'result' field not found in JSON data.")
            except json.JSONDecodeError:
                # Not a JSON object, check if it's printable text
                if text.isprintable():
                    print("[+] Decrypted Content:\n", text)
                else:
                    handle_binary_data(decrypted_data, args.output_file)
        except UnicodeDecodeError:
            # Binary data, attempt to handle as zlib-compressed data
            handle_binary_data(decrypted_data, args.output_file)
    else:
        print("[-] Failed to decrypt data.")


def handle_binary_data(decrypted_data: bytes, output_file: str):
    """Attempts to decompress zlib-compressed data or saves binary data to a file."""
    try:
        decompressed_data = zlib.decompress(decrypted_data)
        print("[+] Decrypted data is zlib-compressed. Decompressed successfully.")
        try:
            decompressed_text = decompressed_data.decode('utf-8')
            print("[+] Decompressed Text:\n", decompressed_text)
        except UnicodeDecodeError:
            output_file = output_file or 'decompressed_output.bin'
            with open(output_file, 'wb') as f:
                f.write(decompressed_data)
            print(f"[+] Decompressed binary data saved to '{output_file}'.")
    except zlib.error:
        # If data is not zlib-compressed, save original binary data (most likely a decryption error occured)
        output_file = output_file or 'output.bin'
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        print(f"[+] Decrypted binary data saved to '{output_file}'.")


def main():
    args = parse_arguments()

    if args.mode == 'recover':
        handle_recover_mode(args)
    elif args.mode == 'decrypt':
        handle_decrypt_mode(args)
    else:
        print("[-] Unknown mode. Use 'recover' or 'decrypt'.")
        sys.exit(1)


if __name__ == "__main__":
    main()
