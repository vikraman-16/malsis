import hashlib
import os

# 1. Hash files
def hash_file(file):
    try:
        hash_value = hashlib.sha256(open(file, "rb").read()).hexdigest()
        print(f"SHA256 Hash: {hash_value}")
    except Exception as e:
        print(f"Error hashing file: {e}")

# 2. Detect PE files
def detect_pe(file):
    try:
        with open(file, "rb") as f:
            magic_number = f.read(2)
        if magic_number == b"MZ":
            print("PE Detected")
        else:
            print("Not PE")
    except Exception as e:
        print(f"Error detecting PE: {e}")

# 3. Process listing
def list_processes():
    try:
        os.system("tasklist")
    except Exception as e:
        print(f"Error listing processes: {e}")

# 4. Malware signature search
def signature_search(file, signature):
    try:
        with open(file, "rb") as f:
            content = f.read()
        if signature.encode() in content:
            print("Found")
        else:
            print("Not Found")
    except Exception as e:
        print(f"Error searching signature: {e}")

# 5. Sandbox execution (Linux only)
def sandbox_exec(cmd):
    try:
        os.system(f"firejail {cmd}")
    except Exception as e:
        print(f"Error executing in sandbox: {e}")

def main():
    # Example usage
    print("Malware Analysis Toolkit")
    file = "example.exe"  # Replace with your file path
    signature = "malware_signature"  # Replace with the actual signature

    # Call the functions
    hash_file(file)
    detect_pe(file)
    list_processes()
    signature_search(file, signature)

    # Sandbox execution (Linux only, commented out for safety)
    # sandbox_exec("ls")  # Replace 'ls' with the command to be sandboxed

if __name__ == "__main__":
    main()