import socket
import threading
import random
import string
import sys
from aes import aes_encrypt

KDC_HOST = "0.0.0.0"
KDC_PORT = 7000

# Default master keys (16 ASCII characters)
keys_db = {
    "Alice": "MasterKeyAlice12",
    "Bob": "MasterKeyBob1234"
}

history_log = []
running = True

def generate_session_key(length=16):
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))

def handle_client(conn, addr):
    try:
        raw_data = conn.recv(2048).decode('ascii').strip()
        if not raw_data:
            conn.close()
            return
            
        print(f"\n[KDC] Incoming connection from {addr}")
        print(f"[KDC] [Step 1 Received]: {raw_data}")
        
        parts = raw_data.split(",")
        if len(parts) == 3:
            id_a, id_b, n1 = parts[0].strip(), parts[1].strip(), parts[2].strip()
            
            if id_a not in keys_db or id_b not in keys_db:
                print(f"[KDC] [Error]: Unknown entity '{id_a}' or '{id_b}'")
                conn.send(b"ERROR: Unknown entity\n")
                conn.close()
                return
                
            ka = keys_db[id_a]
            kb = keys_db[id_b]
            
            # Step 2: Generate Session Key (Ks)
            ks = generate_session_key(16)
            print(f"[KDC] Generated Session Key (Ks): {ks}")
            print(f"[KDC] Master Key A ({id_a}): {ka}")
            print(f"[KDC] Master Key B ({id_b}): {kb}")
            
            # Ticket_B = E(Kb, [Ks || IDA])
            ticket_b_plain = f"{ks},{id_a}"
            ticket_b_hex = aes_encrypt(ticket_b_plain, kb)
            print(f"[KDC] Generated Ticket_B (Hex): {ticket_b_hex}")
            
            # Step 2 message = E(Ka, [Ks || IDB || N1 || Ticket_B])
            msg2_plain = f"{ks},{id_b},{n1},{ticket_b_hex}"
            msg2_hex = aes_encrypt(msg2_plain, ka)
            print(f"[KDC] [Step 2 Sending to {id_a}] (Hex): {msg2_hex}")
            
            conn.send((msg2_hex + "\n").encode('ascii'))
            
            log_entry = f"Alice={id_a}, Bob={id_b}, N1={n1}, Ks={ks}"
            history_log.append(log_entry)
        else:
            print(f"[KDC] Invalid message format: {raw_data}")
            conn.send(b"ERROR: Invalid format\n")
    except Exception as e:
        print(f"[KDC] Error handling client: {e}")
    finally:
        conn.close()
        print("KDC > ", end="", flush=True)

def server_worker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((KDC_HOST, KDC_PORT))
    server.listen(5)
    server.settimeout(1.0)
    
    while running:
        try:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            client_thread.start()
        except socket.timeout:
            continue
        except Exception as e:
            if running:
                print(f"[KDC] Listener error: {e}")
            break
            
    server.close()

def print_help():
    print("\n--- KDC Console Commands ---")
    print("1. keys              : Display current Master Keys")
    print("2. setka <new_key>   : Change Alice's Master Key")
    print("3. setkb <new_key>   : Change Bob's Master Key")
    print("4. history           : View session key distribution history")
    print("5. help              : Display this help message")
    print("6. exit              : Shut down KDC")
    print("----------------------------\n")

def main():
    global running
    print("==========================================")
    print("     KEY DISTRIBUTION CENTER (KDC)        ")
    print(f"     Listening on {KDC_HOST}:{KDC_PORT}   ")
    print("==========================================")
    print(f"Initial Master Key Alice (Ka) : {keys_db['Alice']}")
    print(f"Initial Master Key Bob   (Kb) : {keys_db['Bob']}")
    print_help()
    
    server_thread = threading.Thread(target=server_worker, daemon=True)
    server_thread.start()
    
    while running:
        try:
            cmd = input("KDC > ").strip()
            if not cmd:
                continue
                
            parts = cmd.split(maxsplit=1)
            action = parts[0].lower()
            
            if action in ["1", "keys"]:
                print(f"[KDC Keys] Alice (Ka): {keys_db['Alice']}")
                print(f"[KDC Keys] Bob   (Kb): {keys_db['Bob']}")
            elif action in ["2", "setka"]:
                if len(parts) > 1 and parts[1].strip():
                    new_key = parts[1].strip()
                    keys_db["Alice"] = new_key
                    print(f"[KDC] Alice's Master Key updated to: {new_key}")
                else:
                    new_key = input("Enter new Master Key for Alice: ").strip()
                    if new_key:
                        keys_db["Alice"] = new_key
                        print(f"[KDC] Alice's Master Key updated to: {new_key}")
            elif action in ["3", "setkb"]:
                if len(parts) > 1 and parts[1].strip():
                    new_key = parts[1].strip()
                    keys_db["Bob"] = new_key
                    print(f"[KDC] Bob's Master Key updated to: {new_key}")
                else:
                    new_key = input("Enter new Master Key for Bob: ").strip()
                    if new_key:
                        keys_db["Bob"] = new_key
                        print(f"[KDC] Bob's Master Key updated to: {new_key}")
            elif action in ["4", "history"]:
                print("\n--- Distribution History ---")
                if not history_log:
                    print("No distribution sessions recorded yet.")
                else:
                    for idx, h in enumerate(history_log, 1):
                        print(f"{idx}. {h}")
                print("----------------------------\n")
            elif action in ["5", "help"]:
                print_help()
            elif action in ["6", "exit", "quit"]:
                print("[KDC] Shutting down...")
                running = False
                break
            else:
                print(f"[KDC] Unknown command: '{cmd}'. Type 'help' for options.")
        except (KeyboardInterrupt, EOFError):
            print("\n[KDC] Stopping...")
            running = False
            break

if __name__ == "__main__":
    main()