import random
import binascii
import hashlib
import hmac
from binascii import hexlify


print("Unique a-nonce, s-nonce, PTK and MIC generated in a single AP-Client\n"
      "connectivity session")
print("Note that if SSID or password don't change, PMK will remain constant\n"
      "across sessions")
print("#########################################################################")
# Parameters
password   = "admin123"
ssid       = "iamtonystark13"
ap_mac     = "00:11:22:33:44:55"
client_mac = "66:77:88:99:aa:bb"

password_bytes = password.encode('utf-8')
ssid_bytes = ssid.encode('utf-8')
ap_mac_bytes = binascii.unhexlify(ap_mac.replace(':', ''))
client_mac_bytes = binascii.unhexlify(client_mac.replace(':', ''))

def generate_anonce(length):
    # Define the characters to be used for generating the nonce
    characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    # Generate a random nonce of the specified length
    nonce = ""
    for _ in range(length):
        nonce += random.choice(characters)

    return nonce

def generate_snonce(length):
    # Define the characters to be used for generating the nonce
    characters = "0113451789ABC1EFG1IJK1MNO1QRS1UVW1YZa1cde1ghij1lmnop1rstu1wx1z"

    # Generate a random nonce of the specified length
    nonce = ""
    for _ in range(length):
        nonce += random.choice(characters)

    return nonce

def calculate_ptk(pmk, anonce, snonce, ap_mac, client_mac):
    # Generate PTK using HMAC-SHA1 as the PRF
    ptk = hmac.new(pmk, b"Pairwise key expansion", hashlib.sha1)
    ptk.update(min(ap_mac, client_mac) + max(ap_mac, client_mac))
    ptk.update(min(anonce, snonce) + max(anonce, snonce))
    ptk = ptk.digest()
    return ptk

def calculate_pmk(password, ssid):
    # Convert password and SSID to bytes
    password_bytes = password.encode('utf-8')
    ssid_bytes = ssid.encode('utf-8')

    # Calculate PMK using PBKDF2-HMAC-SHA
    # 4096 : The number of iterations to apply the HMAC-SHA1 
    #        function during the key derivation process. A higher 
    #        iteration count increases the computational cost, 
    #        making it harder for attackers to guess the password.
    # 32   : The length of the output key in bytes. In this case, 
    #        the PMK will be 32 bytes long. 
    pmk = hashlib.pbkdf2_hmac('sha1', password_bytes, ssid_bytes, 4096, 32)

    return pmk

def calculate_mic(ptk, ap_mac, client_mac, anonce, snonce):
    # Use SHA-256 as the hashing algorithm
    hashing_algorithm = hashlib.sha256()

    # Calculate the MIC by applying SHA-256 to the input data
    hashing_algorithm.update(ptk + ap_mac + client_mac + anonce + snonce)
    mic = hashing_algorithm.digest()

    return mic

# Specify the length of the nonce
nonce_length = 16
# AP Generate A-nonce to share with the Client
a_nonce = generate_anonce(nonce_length)

# AP Generate A-nonce to share with the Client
s_nonce = generate_snonce(nonce_length)

# Print the generated nonce
print("AP Generated a-Nonce:", a_nonce)
print("Client Generated s-Nonce:", s_nonce)


'''
 * ################################################################
 * Summary of Steps:
 * ################################################################
 * 1. Generate PMK (Pairwise Master Key) using the password and SSID.
 * 2. Calculate the PTK (Pairwise Transient Key) using 
 *    the PMK, ANonce, SNonce, AP MAC address, and client MAC address.
 * 3. Generate M3 by providing the data for MIC calculation.
 * 4. Calculate the MIC (Message Integrity Code) using AES-128-CMAC 
 *    and the PTK.
 * 5. Print the PTK and MIC values.
'''

'''
The generation of the Pairwise Master Key (PMK) involves the 
following ingredients:
1. Password: It is a shared secret between the client and the AP. 
   The password is typically a human-readable string chosen by the 
   network administrator or the user.

2. SSID (Service Set Identifier): It is the network identifier for 
   the Wi-Fi network. The SSID is typically broadcasted by the AP 
   and is used by the client to identify and join the desired network.

To generate the PMK, a 'key derivation function' is applied to the 
password and SSID. The 'key derivation function' is designed to be 
computationally expensive, making it more difficult for attackers to 
perform brute-force or dictionary attacks.

One commonly used key derivation function for generating the PMK is 
the PBKDF2 (Password-Based Key Derivation Function 2) with HMAC-SHA1 
(Hashed Message Authentication Code-Secure Hash Algorithm 1) as the 
underlying pseudorandom function (PRF). PBKDF2 iteratively applies 
the HMAC-SHA1 function multiple times to derive a key of the desired 
length.

The inputs to the PBKDF2 function for PMK generation are:
===================================================================
Password: The shared secret between the client and the AP.
Salt: The SSID of the Wi-Fi network.
Iterations: The number of iterations to apply the HMAC-SHA1 function.
Key length: The desired length of the PMK.

By applying the PBKDF2 function with the specified inputs, the 
PMK is generated as the output. The PMK serves as the foundation 
for deriving other session keys, such as the Pairwise Transient Key 
(PTK), which is used for secure communication between the client and 
the AP during the 4-way handshake in WPA2.
'''
pmk = calculate_pmk(password, ssid)
pmk_hex = hexlify(pmk).decode('utf-8')
print("PMK:", pmk_hex)


###########################################################################
# The Pairwise Transient Key (PTK) is calculated using the following steps:
###########################################################################
# 1. Generate a PTK using HMAC-SHA1 as the pseudorandom function (PRF).
# 2. Update the PTK with specific inputs, 
#    including the AP MAC address, client MAC address, 
#    ANonce, and SNonce.

###########################################################################
#  Here is a breakdown of the PTK calculation:
###########################################################################
# Initialize the PTK with the PMK (Pairwise Master Key):
#   Use HMAC-SHA1 as the PRF (pseudorandom function).
#   The PRF is used to derive keys based on the PMK.
#   The "Pairwise key expansion" string is used as the initial input for 
#   the PRF.

# Update the PTK with additional inputs:
#   Concatenate the AP MAC address and client MAC address.
#   Concatenate the ANonce and SNonce.
#   Update the PTK with these concatenated values using the PRF.

# Obtain the final PTK:
# Obtain the PTK by digesting the updated PTK value.
# The resulting digest represents the calculated PTK.
ptk = calculate_ptk(pmk, 
                    a_nonce.encode('utf-8'), 
                    s_nonce.encode('utf-8'), 
                    ap_mac_bytes, client_mac_bytes)
ptk_hex = hexlify(ptk).decode('utf-8')
print("PTK:", ptk_hex)

######################################################################
# The MIC (Message Integrity Code) is used as part of the 4-way handshake 
# process in WPA2 (Wi-Fi Protected Access 2) to ensure the integrity of the 
# handshake messages. The MIC is included in the handshake messages to 
# detect any tampering or unauthorized modifications.

# During the 4-way handshake, the following steps occur:
# =================================================================
#  The access point (AP) sends a message (M1) to the client, 
#  which includes the AP's nonce (ANonce).

#  The client receives the M1 message and generates its own 
#  nonce (SNonce). It then calculates the Pairwise Transient Key 
#  (PTK) using the PMK (Pairwise Master Key), the nonces (ANonce and 
#  SNonce), and other parameters.

#  The client sends a message (M2) to the AP, which includes the 
#  client's nonce (SNonce) and the MIC calculated based on the PTK, 
#  MAC addresses, and nonces.

#  The AP receives the M2 message and calculates its own PTK using 
#  the same parameters as the client. It then verifies the received 
#  MIC by independently calculating it based on the received values.
#  If the calculated MIC matches the received MIC, it indicates that 
#  the handshake messages were not tampered with during transmission. 
#  The AP and client can proceed with the handshake and establish a 
#  secure connection.

#  The MIC is crucial for ensuring the integrity of the handshake 
#  messages and preventing potential attacks, such as message modification 
#  or replay attacks. It acts as a cryptographic checksum that allows both 
#  the AP and client to verify the authenticity and integrity of the 
#  handshake messages exchanged between them.
######################################################################

# Calculate MIC using the generated PTK, MAC addresses, and nonces
mic = calculate_mic(ptk, 
                    ap_mac_bytes, 
                    client_mac_bytes, 
                    a_nonce.encode('utf-8'), 
                    s_nonce.encode('utf-8'))
mic_hex = hexlify(mic).decode('utf-8')
print("MIC:", mic_hex)
