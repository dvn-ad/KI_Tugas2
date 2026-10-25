import socket
import random
import threading

# Include aes_encrypt and aes_decrypt helper functions from bob.py

KDC_IP = "192.168.1.10"  # Set to actual KDC IP
KDC_PORT = 7000

BOB_IP = "192.168.1.12"   # Set to actual Bob IP
BOB_PORT = 8000

KEY_A = "MasterKeyAlice12"

def start_alice():
    # --- PHASE 1: KDC HANDSHAKE ---
    print("=== ALICE INITIATING KDC HANDSHAKE ===")
    n1 = str(random.randint(1000, 9999))
    msg1 = f"Alice,Bob,{n1}"
    
    # Connect to KDC
    kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_sock.connect((KDC_IP, KDC_PORT))
    kdc_sock.send(msg1.encode('ascii'))
    
    # Receive Pesan 2 from KDC
    msg2_hex = kdc_sock.recv(2048).decode('ascii').strip()
    kdc_sock.close()
    
    # Decrypt Pesan 2 using KEY_A
    msg2_raw = aes_decrypt(msg2_hex, KEY_A)
    k_ab, id_b, recv_n1, ticket_b_hex = msg2_raw.split(",")
    
    assert n1 == recv_n1, "Nonce N1 mismatch! Replay attack detected."
    print(f"[+] Handshake Step 2 Success! Obtained K_AB: {k_ab}")
    
    # --- PHASE 2: DIRECT CHAT WITH BOB ---
    bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_sock.connect((BOB_IP, BOB_PORT))
    
    # Step 3: Send Ticket_B + Encrypted N2 to Bob
    n2 = random.randint(10000, 99999)
    enc_n2_hex = aes_encrypt(str(n2), k_ab)
    msg3 = f"{ticket_b_hex};{enc_n2_hex}"
    bob_sock.send(msg3.encode('ascii'))
    
    # Step 4 & 5: Receive and verify f(N2) = N2 - 1
    msg4_hex = bob_sock.recv(1024).decode('ascii').strip()
    ans_n2 = int(aes_decrypt(msg4_hex, k_ab))
    
    if ans_n2 == n2 - 1:
        print("[+] Step 5 Verified! Bob authenticated. Direct encrypted chat active.\n")
    else:
        print("[-] Authentication failed!")
        return

    # Receiver Thread
    def receive_chat():
        while True:
            try:
                hex_msg = bob_sock.recv(1024).decode('ascii').strip()
                if not hex_msg: break
                plain = aes_decrypt(hex_msg, k_ab)
                print(f"\n[Bob (Hex: {hex_msg[:8]}...)]: {plain}\nAlice > ", end="")
            except:
                break
                
    threading.Thread(target=receive_chat, daemon=True).start()

    # Chat Loop
    while True:
        msg = input("Alice > ")
        if msg.lower() == 'exit': break
        hex_out = aes_encrypt(msg, k_ab)
        bob_sock.send(hex_out.encode('ascii'))

if __name__ == "__main__":
    start_alice()