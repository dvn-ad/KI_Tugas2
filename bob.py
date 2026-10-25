import socket
import threading
import random
import select
import sys
from aes import aes_encrypt, aes_decrypt

BOB_HOST = "0.0.0.0"
BOB_PORT = 8000

KEY_B = "MasterKeyBob1234"
SESSION_KEY_AB = None

def handle_chat_session(conn, addr, kb):
    global SESSION_KEY_AB
    try:
        conn_file = conn.makefile('r', encoding='ascii')
        print(f"\n[+] Incoming connection from {addr}")
        
        # Step 3: Receive Ticket_B from Alice
        print("[*] Waiting for Step 3 (Ticket_B) from Alice...")
        line = conn_file.readline()
        if not line:
            conn.close()
            return
        ticket_b_hex = line.strip()
        print(f"[Step 3 Received Ticket_B (Hex)]: {ticket_b_hex}")
        
        # Decrypt Ticket_B using Bob's Master Key (Kb)
        try:
            ticket_plain = aes_decrypt(ticket_b_hex, kb)
        except Exception as e:
            print(f"[-] Failed to decrypt Ticket_B with Master Key Kb: {e}")
            conn.send(b"ERROR: Ticket decryption failed\n")
            conn.close()
            return
            
        print(f"[+] Decrypted Ticket_B: '{ticket_plain}'")
        parts = ticket_plain.split(",")
        if len(parts) != 2:
            print(f"[-] Malformed Ticket_B content: {ticket_plain}")
            conn.close()
            return
            
        ks, id_a = parts[0].strip(), parts[1].strip()
        SESSION_KEY_AB = ks
        print(f"[+] Authenticated Client Identity: {id_a}")
        print(f"[+] Extracted Session Key (Ks): {ks}")
        
        # Step 4: Generate Nonce N2 and send E(Ks, N2) to Alice
        n2 = random.randint(100000, 999999)
        print(f"[+] Generated Challenge Nonce (N2): {n2}")
        
        enc_n2_hex = aes_encrypt(str(n2), ks)
        print(f"[Step 4 Sending to {id_a}] E(Ks, N2) (Hex): {enc_n2_hex}")
        conn.send((enc_n2_hex + "\n").encode('ascii'))
        
        # Step 5: Receive E(Ks, f(N2)) from Alice
        print("[*] Waiting for Step 5 from Alice...")
        step5_line = conn_file.readline()
        if not step5_line:
            conn.close()
            return
        step5_hex = step5_line.strip()
        print(f"[Step 5 Received] E(Ks, f(N2)) (Hex): {step5_hex}")
        
        try:
            ans_plain = aes_decrypt(step5_hex, ks)
            ans_n2 = int(ans_plain.strip())
        except Exception as e:
            print(f"[-] Failed to decrypt Step 5: {e}")
            conn.send(b"ERROR: Step 5 failed\n")
            conn.close()
            return
            
        expected_fn2 = n2 - 1
        print(f"[+] Decrypted f(N2): {ans_n2} (Expected: {expected_fn2})")
        
        if ans_n2 == expected_fn2:
            print("\n=======================================================")
            print(" [+] STEP 5 VERIFIED! Alice authenticated successfully.")
            print(f" [+] Mutual Session Key: {ks}")
            print(" [+] Two-Way Encrypted Chat is now ACTIVE!")
            print("=======================================================")
            
            # Send confirmation to Alice
            auth_ok_hex = aes_encrypt("AUTH_OK", ks)
            conn.send((auth_ok_hex + "\n").encode('ascii'))
        else:
            print("[-] Nonce verification failed! Replay attack or impostor.")
            conn.send(b"ERROR: Nonce mismatch\n")
            conn.close()
            return
            
        # --- TWO-WAY CHAT SESSION ---
        chat_active = True
        
        def receive_chat():
            nonlocal chat_active
            while chat_active:
                try:
                    data = conn_file.readline()
                    if not data:
                        print(f"\n[Chat] {id_a} disconnected.")
                        chat_active = False
                        break
                    data = data.strip()
                    if not data:
                        continue
                    if data == "/exit":
                        print(f"\n[Chat] {id_a} ended the chat.")
                        chat_active = False
                        break
                        
                    plain = aes_decrypt(data, ks)
                    print(f"\n[{id_a}] Ciphertext (Hex): {data}")
                    print(f"[{id_a}] Plaintext       : {plain}")
                    print("Bob > ", end="", flush=True)
                except Exception as e:
                    if chat_active:
                        print(f"\n[Chat] Receive/Decryption Error: {e}")
                    chat_active = False
                    break
                    
        recv_thread = threading.Thread(target=receive_chat, daemon=True)
        recv_thread.start()
        
        print("\nType your message and press Enter. Commands: /info, /exit\n")
        print("Bob > ", end="", flush=True)
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
                        print("Bob > ", end="", flush=True)
                        continue
                    if msg.lower() == "/exit":
                        try:
                            conn.send(b"/exit\n")
                        except:
                            pass
                        chat_active = False
                        break
                    elif msg.lower() == "/info":
                        print(f"[Info] Active Partner: {id_a} | Session Key (Ks): {ks}")
                        print("Bob > ", end="", flush=True)
                        continue
                        
                    hex_ct = aes_encrypt(msg, ks)
                    print(f"[Sent] Ciphertext (Hex): {hex_ct}")
                    conn.send((hex_ct + "\n").encode('ascii'))
                    print("Bob > ", end="", flush=True)
            except (KeyboardInterrupt, EOFError):
                try:
                    conn.send(b"/exit\n")
                except:
                    pass
                chat_active = False
                break
                
    except Exception as e:
        print(f"[-] Session error: {e}")
    finally:
        conn.close()
        print("\n[+] Session closed. Returning to listening mode...\n")

def run_bob():
    global KEY_B, BOB_PORT
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BOB_HOST, BOB_PORT))
    except Exception as e:
        print(f"[-] Could not bind to port {BOB_PORT}: {e}")
        return
        
    server.listen(5)
    print("==========================================")
    print("               BOB NODE                   ")
    print(f"   Listening on {BOB_HOST}:{BOB_PORT}     ")
    print(f"   Current Master Key Bob (Kb): {KEY_B}  ")
    print("==========================================")
    print("[*] Ready and listening for incoming handshake from Alice...")
    print("Commands: 'setkb <new_key>', 'keys', 'aes', 'exit'\n")
    print("Bob > ", end="", flush=True)
    
    while True:
        try:
            rlist, _, _ = select.select([sys.stdin, server], [], [])
            
            if server in rlist:
                conn, addr = server.accept()
                handle_chat_session(conn, addr, KEY_B)
                print("[*] Ready and listening for incoming handshake from Alice...")
                print("Bob > ", end="", flush=True)
                
            if sys.stdin in rlist:
                line = sys.stdin.readline()
                if not line:
                    break
                cmd = line.strip()
                if not cmd:
                    print("Bob > ", end="", flush=True)
                    continue
                parts = cmd.split(maxsplit=1)
                action = parts[0].lower()
                
                if action == "keys":
                    print(f"[Bob] Master Key Bob (Kb): {KEY_B}")
                elif action == "setkb":
                    if len(parts) > 1 and parts[1].strip():
                        KEY_B = parts[1].strip()
                        print(f"[+] Master Key Bob updated to: {KEY_B}")
                    else:
                        new_k = input("Enter new Master Key for Bob: ").strip()
                        if new_k:
                            KEY_B = new_k
                            print(f"[+] Master Key Bob updated to: {KEY_B}")
                elif action == "aes":
                    txt = input("Plaintext: ")
                    c = aes_encrypt(txt, KEY_B)
                    print(f"Ciphertext (Hex): {c}")
                    print(f"Decrypted: {aes_decrypt(c, KEY_B)}")
                elif action in ["exit", "quit"]:
                    print("Exiting Bob node.")
                    break
                else:
                    print(f"Unknown command: '{cmd}'. Commands: 'setkb <new_key>', 'keys', 'aes', 'exit'")
                print("Bob > ", end="", flush=True)
        except (KeyboardInterrupt, EOFError):
            print("\nExiting Bob node.")
            break
            
    server.close()

if __name__ == "__main__":
    run_bob()