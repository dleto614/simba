import re
import struct
import sys
import binascii

def parse_ntlm_type2_message(hex_data):
    """
    Parses an NTLM Type 2 message to extract the 8-byte server challenge.
    The challenge is located at bytes 24-31.
    """
    try:
        if len(hex_data) < 32:
            return None
        challenge_bytes = hex_data[24:32]
        challenge_str = binascii.hexlify(challenge_bytes).decode('utf-8')
        return challenge_str
    except Exception:
        return None

def parse_ntlm_type3_message(hex_data):
    """
    Parses an NTLM Type 3 message to extract user, domain, and the full NTLMv2 response.
    It then splits the response into NTProofStr and Blob.
    """
    try:
        if len(hex_data) < 64:
            return None

        nt_resp_len, nt_resp_offset = struct.unpack('<HxxI', hex_data[20:28])
        domain_len, domain_offset = struct.unpack('<HxxI', hex_data[28:36])
        user_len, user_offset = struct.unpack('<HxxI', hex_data[36:44])

        nt_response_hex = binascii.hexlify(hex_data[nt_resp_offset:nt_resp_offset+nt_resp_len]).decode('utf-8')
        ntproof_str = nt_response_hex[:32]
        blob = nt_response_hex[32:]

        domain = hex_data[domain_offset:domain_offset+domain_len].decode('utf-16le')
        user = hex_data[user_offset:user_offset+user_len].decode('utf-16le')

        return {
            "user": user,
            "domain": domain,
            "ntproof_str": ntproof_str,
            "blob": blob
        }
    except Exception:
        return None

def extract_ntlmv2_hashes_from_log(log_file_path):
    """
    Reads a log file, extracts NTLM Type 2 and Type 3 messages from both
    'Token:' and 'handleNegotiate:' lines, and reconstructs them into
    JtR-compatible NetNTLMv2 hashes.
    """
    print(f"[*] Parsing log file: {log_file_path}")
    
    token_pattern = re.compile(r'Token: ([a-fA-F0-9]+)')
    negotiate_pattern = re.compile(r'handleNegotiate: ([a-fA-F0-9]+)')

    last_challenge = None
    found_hashes_list = []

    with open(log_file_path, 'r') as f:
        for line in f:
            # Check for the Type 2 message in a 'handleNegotiate' line
            negotiate_match = negotiate_pattern.search(line)
            if negotiate_match:
                hex_string = negotiate_match.group(1)
                ntlmssp_signature_hex = "4e544c4d535350"
                ntlm_start_index = hex_string.find(ntlmssp_signature_hex)
                
                if ntlm_start_index != -1:
                    ntlm_hex_string = hex_string[ntlm_start_index:]
                    ntlm_hex_data = binascii.unhexlify(ntlm_hex_string)
                    if len(ntlm_hex_data) >= 12:
                        message_type = struct.unpack('<I', ntlm_hex_data[8:12])[0]
                        if message_type == 2:
                            last_challenge = parse_ntlm_type2_message(ntlm_hex_data)
                continue

            # Check for Type 1, 2, or 3 messages in 'Token' lines
            token_match = token_pattern.search(line)
            if not token_match:
                continue

            hex_string = token_match.group(1)
            hex_data = binascii.unhexlify(hex_string)

            if len(hex_data) < 12:
                continue
            
            message_type = struct.unpack('<I', hex_data[8:12])[0]

            if message_type == 2:
                last_challenge = parse_ntlm_type2_message(hex_data)
            
            elif message_type == 3:
                if not last_challenge:
                    continue
                
                auth_data = parse_ntlm_type3_message(hex_data)
                if auth_data:
                    user = auth_data['user']
                    domain = auth_data['domain']
                    challenge = last_challenge
                    ntproof_str = auth_data['ntproof_str']
                    blob = auth_data['blob']

                    # *** CORRECTION: Ensure all components are non-empty ***
                    if not all([user, domain, challenge, ntproof_str, blob]):
                        # If any component is missing or empty, skip this one
                        continue

                    jtr_hash = f"{user}::{domain}:{challenge}:{ntproof_str}:{blob}"
                    found_hashes_list.append(jtr_hash)

    # Print all collected hashes at the end
    if found_hashes_list:
        print(f"\n[+] Found {len(found_hashes_list)} NetNTLMv2 Hash(es):")
        for h in found_hashes_list:
            print(h)
    else:
        print("\n[-] No valid NetNTLMv2 hashes found in the log file.")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python extract-hashes.py <log_file_path>")
        sys.exit(1)
        
    log_path = sys.argv[1]
    extract_ntlmv2_hashes_from_log(log_path)
