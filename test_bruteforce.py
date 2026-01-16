import time
import random

def brute_force_attack(target_ip, num_attempts=10):
    print(f"[INFO] Launching brute force attack on {target_ip}")

    for i in range(1, num_attempts + 1):
        username = "admin"
        password = f"password{i}"

        print(f"[ATTEMPT {i}] Trying {username}:{password}")
        time.sleep(0.5)

    print("[INFO] Bruteforce attack finished")


if __name__ == "__main__":
    brute_force_attack(target_ip="172.20.10.5", num_attempts=15)
