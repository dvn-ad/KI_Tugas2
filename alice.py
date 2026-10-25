import socket
import threading
import random
import select
import sys
from aes import aes_encrypt, aes_decrypt

# Default addresses and keys
KDC_IP = "172.20.0.10"
KDC_PORT = 7000

BOB_IP = "172.20.0.12"
BOB_PORT = 8000

KEY_A = "MasterKeyAlice12"

def initiate_kdc_handshake(ka, kdc_ip, kdc_port, bob_ip, bob_port):
    print("\n=======================================================")
    print("      PHASE 1: KEY DISTRIBUTION (KDC HANDSHAKE)       ")
    print("=======================================================")
    
    # Step 1: Alice -> KDC
    n1 = str(random.randint(100000, 999999))
    msg1 = f"Alice,Bob,{n1}"
    print(f"[*] Connecting to KDC at {kdc_ip}:{kdc_port}...")
    
    try:
        kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        kdc_sock.settimeout(5.0)
        kdc_sock.connect((kdc_ip, kdc_port))
    except Exception as e:
        print(f"[-] Failed to connect to KDC ({kdc_ip}:{kdc_port}): {e}")
        return None
        
    print(f"[Step 1 Sending to KDC]: {msg1}")
    kdc_sock.send((msg1 + "\n").encode('ascii'))
    
    # Step 2: KDC -> Alice
    try:
        msg2_hex = kdc_sock.recv(4096).decode('ascii').strip()
    except Exception as e:
        print(f"[-] Error receiving response from KDC: {e}")
        kdc_sock.close()
        return None
    kdc_sock.close()
    
    if not msg2_hex or msg2_hex.startswith("ERROR"):
        print(f"[-] KDC returned error or empty response: {msg2_hex}")
        return None
        
    print(f"[Step 2 Received from KDC] (Hex): {msg2_hex}")
    
    # Decrypt Step 2 message with Alice's Master Key (Ka)
    try:
        msg2_plain = aes_decrypt(msg2_hex, ka)
    except Exception as e:
        print(f"[-] Decryption of Step 2 failed with Master Key Ka: {e}")
        print("    (Check if Alice's Master Key matches the one registered in KDC!)")
        return None
        
    print(f"[+] Decrypted Step 2 Plaintext: {msg2_plain}")
    parts = msg2_plain.split(",")
    if len(parts) != 4:
        print(f"[-] Unexpected format in decrypted Step 2: {msg2_plain}")
        return None
        
    ks, id_b, recv_n1, ticket_b_hex = parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()
    
    if recv_n1 != n1:
        print(f"[-] Replay attack or corrupted Nonce! (Sent: {n1}, Recv: {recv_n1})")
        return None
    if id_b != "Bob":
        print(f"[-] Target ID mismatch! (Expected: Bob, Recv: {id_b})")
        return None
        
    print(f"[+] Nonce N1 ({n1}) and ID_B ({id_b}) verified!")
    print(f"[+] Established Session Key (Ks): {ks}")
    print(f"[+] Ticket_B for Bob (Hex): {ticket_b_hex}")
    
    # --- PHASE 2: MUTUAL AUTHENTICATION WITH BOB ---
    print("\n=======================================================")
    print("      PHASE 2: DIRECT HANDSHAKE WITH BOB               ")
    print("=======================================================")
    print(f"[*] Connecting to Bob at {bob_ip}:{bob_port}...")
    
    try:
        bob_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_sock.settimeout(10.0)
        bob_sock.connect((bob_ip, bob_port))
    except Exception as e:
        print(f"[-] Failed to connect to Bob ({bob_ip}:{bob_port}): {e}")
        return None
        
    bob_file = bob_sock.makefile('r', encoding='ascii')
    
    # Step 3: Alice -> Bob (Send Ticket_B)
    print(f"[Step 3 Sending Ticket_B to Bob] (Hex): {ticket_b_hex}")
    bob_sock.send((ticket_b_hex + "\n").encode('ascii'))
    
    # Step 4: Bob -> Alice (Receive Challenge Nonce N2)
    print("[*] Waiting for Step 4 from Bob...")
    try:
        line = bob_file.readline()
        step4_hex = line.strip()
    except Exception as e:
        print(f"[-] Error receiving Step 4 from Bob: {e}")
        bob_sock.close()
        return None
        
    if not step4_hex or step4_hex.startswith("ERROR"):
        print(f"[-] Bob rejected Step 3 or returned error: {step4_hex}")
        bob_sock.close()
        return None
        
    print(f"[Step 4 Received from Bob] E(Ks, N2) (Hex): {step4_hex}")
    
    try:
        n2_str = aes_decrypt(step4_hex, ks)
        n2 = int(n2_str.strip())
    except Exception as e:
        print(f"[-] Failed to decrypt Step 4 challenge with Ks: {e}")
        bob_sock.close()
        return None
        
    print(f"[+] Decrypted Bob's Challenge Nonce (N2): {n2}")
    
    # Step 5: Alice -> Bob (Respond with f(N2) = N2 - 1)
    fn2 = n2 - 1
    print(f"[+] Calculating f(N2) = N2 - 1 = {fn2}")
    step5_hex = aes_encrypt(str(fn2), ks)
    print(f"[Step 5 Sending to Bob] E(Ks, f(N2)) (Hex): {step5_hex}")
    bob_sock.send((step5_hex + "\n").encode('ascii'))
    
    # Receive Auth Confirmation from Bob
    try:
        confirm_line = bob_file.readline()
        confirm_hex = confirm_line.strip()
        confirm_plain = aes_decrypt(confirm_hex, ks)
    except Exception as e:
        print(f"[-] Did not receive valid confirmation from Bob: {e}")
        bob_sock.close()
        return None
        
    if confirm_plain != "AUTH_OK":
        print(f"[-] Bob did not confirm authentication: {confirm_plain}")
        bob_sock.close()
        return None
        
    print("\n=======================================================")
    print(" [+] STEP 5 COMPLETED & MUTUAL AUTHENTICATION SUCCESS! ")
    print(f" [+] Secure Session Key: {ks}")
    print(" [+] Two-Way Encrypted Chat is now ACTIVE!")
    print("=======================================================")
    
    return bob_sock, bob_file, ks

def start_two_way_chat(bob_sock, bob_file, ks):
    bob_sock.settimeout(None)
    chat_active = True
    
    def receive_chat():
        nonlocal chat_active
        while chat_active:
            try:
                line = bob_file.readline()
                if not line:
                    print("\n[Chat] Bob disconnected.")
                    chat_active = False
                    break
                data = line.strip()
                if not data:
                    continue
                if data == "/exit":
                    print("\n[Chat] Bob has ended the chat.")
                    chat_active = False
                    break
                    
                plain = aes_decrypt(data, ks)
                print(f"\n[Bob] Ciphertext (Hex): {data}")
                print(f"[Bob] Plaintext       : {plain}")
                print("Alice > ", end="", flush=True)
            except Exception as e:
                if chat_active:
                    print(f"\n[Chat] Receive/Decryption Error: {e}")
                chat_active = False
                break
                
    recv_thread = threading.Thread(target=receive_chat, daemon=True)
    recv_thread.start()
    
    print("\nType your message and press Enter. Commands: /info, /exit\n")
    print("Alice > ", end="", flush=True)
    while chat_active:
        try:
            rlist, _, _ = select.select([sys.stdin], [], [], 0.5)
            if not chat_active:
                break
            if rlist:
                line = sys.stdin.readline()
                if not line:
                    chat_active = False
                    break
                msg = line.strip()
                if not msg:
                    print("Alice > ", end="", flush=True)
                    continue
                if msg.lower() == "/exit":
                    try:
                        bob_sock.send(b"/exit\n")
                    except:
                        pass
                    chat_active = False
                    break
                elif msg.lower() == "/info":
                    print(f"[Info] Active Partner: Bob | Session Key (Ks): {ks}")
                    print("Alice > ", end="", flush=True)
                    continue
                    
                hex_ct = aes_encrypt(msg, ks)
                print(f"[Sent] Ciphertext (Hex): {hex_ct}")
                bob_sock.send((hex_ct + "\n").encode('ascii'))
                print("Alice > ", end="", flush=True)
        except (KeyboardInterrupt, EOFError):
            try:
                bob_sock.send(b"/exit\n")
            except:
                pass
            chat_active = False
            break
            
    bob_sock.close()
    print("\n[+] Chat session finished.\n")

def main_menu():
    global KEY_A, KDC_IP, KDC_PORT, BOB_IP, BOB_PORT
    
    while True:
        print("\n=== ALICE CONFIGURATION & CONTROL ===")
        print(f"Alice Master Key (Ka) : {KEY_A}")
        print(f"KDC Target Address    : {KDC_IP}:{KDC_PORT}")
        print(f"Bob Target Address    : {BOB_IP}:{BOB_PORT}")
        print("1. Start Key Distribution & Chat with Bob")
        print("2. Change Alice's Master Key (Ka)")
        print("3. Configure IP & Port Addresses")
        print("4. Manual AES Test (Encrypt & Decrypt)")
        print("5. Exit")
        
        try:
            choice = input("Select [1-5]: ").strip()
            if choice == "1":
                result = initiate_kdc_handshake(KEY_A, KDC_IP, KDC_PORT, BOB_IP, BOB_PORT)
                if result:
                    sock, file_obj, ks = result
                    start_two_way_chat(sock, file_obj, ks)
            elif choice == "2":
                new_key = input("Enter new Master Key for Alice: ").strip()
                if new_key:
                    KEY_A = new_key
                    print(f"[+] Alice Master Key updated to: {KEY_A}")
            elif choice == "3":
                k_ip = input(f"Enter KDC IP (current {KDC_IP}): ").strip()
                if k_ip: KDC_IP = k_ip
                k_port = input(f"Enter KDC Port (current {KDC_PORT}): ").strip()
                if k_port.isdigit(): KDC_PORT = int(k_port)
                b_ip = input(f"Enter Bob IP (current {BOB_IP}): ").strip()
                if b_ip: BOB_IP = b_ip
                b_port = input(f"Enter Bob Port (current {BOB_PORT}): ").strip()
                if b_port.isdigit(): BOB_PORT = int(b_port)
                print("[+] Network addresses updated.")
            elif choice == "4":
                txt = input("Enter plaintext: ")
                k = input(f"Enter key (default {KEY_A}): ").strip() or KEY_A
                c = aes_encrypt(txt, k)
                print(f"Ciphertext (Hex): {c}")
                p = aes_decrypt(c, k)
                print(f"Decrypted: {p}")
            elif choice in ["5", "exit"]:
                print("Exiting Alice node.")
                break
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Alice node.")
            break

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--start":
        result = initiate_kdc_handshake(KEY_A, KDC_IP, KDC_PORT, BOB_IP, BOB_PORT)
        if result:
            sock, file_obj, ks = result
            start_two_way_chat(sock, file_obj, ks)
    else:
        main_menu()