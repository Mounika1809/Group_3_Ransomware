
# Ransomware Simulation Project

This project simulates a ransomware attack and implements strategies for monitoring, detecting, and mitigating such attacks. The project is structured into different components, each focusing on a specific phase of the ransomware lifecycle.

## Project Overview
The ransomware attack is simulated using a malicious PDF exploit. The project follows six key stages:
1. **Research**: Literature review on ransomware techniques.
2. **Encryption**: Implementation of an AES encryption algorithm to encrypt files in a target directory.
3. **Infection**: Creation of a malicious PDF using the Metasploit framework.
4. **Monitoring**: Real-time monitoring of file changes using OSSEC and Python.
5. **Detection**: Identification of ransomware behavior using file integrity checks and hash comparisons.
6. **Mitigation**: Implementation of countermeasures to block file modifications, quarantine infected files, and restore clean backups.

## Installation Instructions
To run this project, follow the steps below to set up the environment:
1. Clone this repository:
   ```bash
   git clone https://github.com/Mounika1809/Group_3_Ransomware
   ```
2. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```
   **Dependencies** include:
   - Python 3.8+
   - OSSEC (for monitoring)
   - Metasploit (for creating malicious PDFs)
   - Required Python libraries: `os`, `watchdog`, `hashlib`, `pycrypto`, etc.

## Code Structure
### 1. **`step 6.ipynb`**: **Mitigation Strategy Implementation**
   - This notebook implements the mitigation strategies, including file permission changes and backup recovery. It also highlights the process of isolating compromised files and restricting access to prevent further damage.
   - First cell code:
     ```python
     # First code snippet from 'step 6.ipynb'
     import os
import shutil
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import psutil

# Function to simulate ransomware encryption (renaming and modifying content)
def simulate_ransomware(file_path):
    try:
        # Renaming the file to add ".enc" extension (simulating encryption)
        new_file_path = file_path + ".enc"
        os.rename(file_path, new_file_path)

        # Modifying the file content (simulating encryption)
        with open(new_file_path, 'w') as f:
            f.write("This file has been encrypted by ransomware!\n")

        print(f"File encrypted: {new_file_path}")
        return new_file_path
    except Exception as e:
        print(f"Error simulating ransomware: {e}")
        return None

# Function to send email alert (to system administrator)
def send_email_alert():
    sender_email = "kevohngatiah27@gmail.com"
    receiver_email = "admin@example.com"  # Change to the actual recipient
    password = "your_email_password"  # Use an app password or a secure way to store it

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = "Ransomware Activity Detected!"

    body = "Ransomware-like activity was detected on your system. Immediate attention is required."
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Gmail SMTP server
        server.starttls()
        server.login(sender_email, password)
        text = msg.as_string()
        server.sendmail(sender_email, receiver_email, text)
        server.quit()
        print("Email alert sent!")
    except Exception as e:
        print(f"Error sending email alert: {e}")

# Function to block access to the file (change permissions)
def block_file_access(file_path):
    try:
        os.chmod(file_path, 0o000)  # Change permissions to deny access
        print(f"Access to {file_path} is blocked.")
    except Exception as e:
        print(f"Error blocking file access: {e}")

# Function to terminate malicious processes (based on process name)
def terminate_malicious_process(process_name):
    for proc in psutil.process_iter(['pid', 'name']):
        if process_name.lower() in proc.info['name'].lower():
            proc.terminate()
            print(f"Terminated process: {proc.info['name']} (PID: {proc.info['pid']})")

# Function to restore file from backup
def restore_from_backup(backup_directory, restore_directory):
    try:
        for filename in os.listdir(backup_directory):
            file_path = os.path.join(backup_directory, filename)
            if os.path.exists(file_path):
                shutil.copy(file_path, restore_directory)
                print(f"Restored {filename} from backup.")
    except Exception as e:
        print(f"Error restoring from backup: {e}")

# Function to quarantine suspicious files (move to quarantine directory)
def quarantine_file(file_path, quarantine_directory):
    try:
        if not os.path.exists(quarantine_directory):
            os.makedirs(quarantine_directory)
        shutil.move(file_path, quarantine_directory)
        print(f"File moved to quarantine: {file_path}")
    except Exception as e:
        print(f"Error moving file to quarantine: {e}")

# Main testing flow
def main():
    victim_file = "/content/malicious.pdf"  # Path to the malicious file
    backup_directory = r"C:\Users\user\Desktop\clean file"  # Clean file backup directory
    quarantine_directory = r"C:\Users\user\Desktop\quarantine"  # Quarantine directory

    # Step 1: Create backup directory and copy a clean file (make sure this exists)
    if not os.path.exists(backup_directory):
        os.makedirs(backup_directory)
    shutil.copy(victim_file, backup_directory)  # Copy a clean version to the backup directory

    # Step 2: Simulate ransomware attack
    encrypted_file = simulate_ransomware(victim_file)

    if encrypted_file:
        # Step 3: Send email alert
        send_email_alert()

        # Step 4: Block file access
        block_file_access(encrypted_file)

        # Step 5: Terminate malicious processes (e.g., named 'ransomware' or 'encryptor')
        terminate_malicious_process('ransomware')

        # Step 6: Restore file from backup
        restore_from_backup(backup_directory, r"C:\Users\user\Desktop")

        # Step 7: Quarantine the encrypted file
        quarantine_file(encrypted_file, quarantine_directory)

if __name__ == "__main__":
    main()

     ```

### 2. **`Detection code.ipynb`**: **Detection Component**
   - This notebook monitors and detects ransomware-like behavior in files by checking for file modifications, renaming patterns (e.g., `.enc`), and integrity violations using hash comparisons.
   - First cell code:
     ```python
     # First code snippet from 'Detection code.ipynb'
     import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# This line define the path to the "malicious.pdf" file which is in the Colab environment
MONITORED_FILE = r"/content/malicious.pdf"

# The hash function meant for file integrity check
def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # This part reads and updates the hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# This dictionary stores original file hash used for comparison
file_hashes = {}

# Initialize file hash
def init_file_hashes():
    print(f"Initializing file hashes for {MONITORED_FILE}...")
    file_hashes[MONITORED_FILE] = get_file_hash(MONITORED_FILE)

# This function defines the rule for detecting ransomware activity
def detect_ransomware(file_path, event_type):
    print(f"Event detected: {event_type} on {file_path}")

    # This condition checks if the file is renamed with '.enc' extension (It is common in ransomware attacks)
    if event_type == 'modified' and file_path.endswith('.enc'):
        print(f"Suspicious activity detected: File renamed to {file_path} (possible ransomware encryption)")
        trigger_mitigation(file_path)

    # This condition checks if the file was modified unexpectedly or not
    if event_type == 'modified' and file_path == MONITORED_FILE:
        print(f"File modification detected: {file_path}")
        # This part compares the current file hash with the original one in order to detect unauthorized changes
        current_hash = get_file_hash(file_path)
        if current_hash != file_hashes.get(file_path):
            print(f"File content has been modified unexpectedly: {file_path}")
            trigger_mitigation(file_path)

def trigger_mitigation(file_path):
    # A sample mitigation: it sends alert and block the file (additional mitigation can be added)
    print(f"Mitigation triggered for {file_path}: Sending alert and blocking file access")
    # It send alert (Which can be an email or message to sysadmin)
    send_alert(file_path)
    # Optionally block file (example for Linux-based systems in Colab)
    os.chmod(file_path, 0o000)  # Change file permissions to prevent further access

def send_alert(file_path):
    # A sample alert function, which sends a simple notification to the system administrator
    print(f"ALERT: Potential ransomware activity detected on {file_path}. Please check the system immediately.")

# This class creates a custom event handler for monitoring the file
class RansomwareDetectorHandler(FileSystemEventHandler):
    def on_modified(self, event):
        print(f"File modified: {event.src_path}")
        if event.is_directory:
            return
        detect_ransomware(event.src_path, 'modified')

    def on_created(self, event):
        print(f"File created: {event.src_path}")
        if event.is_directory:
            return
        detect_ransomware(event.src_path, 'created')

    def on_deleted(self, event):
        print(f"File deleted: {event.src_path}")
        if event.is_directory:
            return
        print(f"File deletion detected: {event.src_path}")

# This is the main function used to set up monitoring
def monitor_files():
    init_file_hashes()  # This initializes the hash table with the current file hash

    event_handler = RansomwareDetectorHandler()
    observer = Observer()

    # This snippet monitors the specific file for changes (It monitors directory only)
    observer.schedule(event_handler, os.path.dirname(MONITORED_FILE), recursive=False)
    observer.start()
    print(f"Monitoring started for {MONITORED_FILE}...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    monitor_files()

     ```

### 3. **`part 2;Action.ipynb`**: **Encryption and Infection Phase**
   - This notebook focuses on the encryption logic and the infection mechanism using Metasploit. It simulates the creation of malicious PDFs that exploit vulnerabilities in outdated PDF readers.
   - First cell code:
     ```python
     # First code snippet from 'part 2;Action.ipynb'
     import os
print("Current working directory:", os.getcwd())

     ```

## Usage Instructions
To run the project, execute the following steps:
1. Open the desired notebook in Jupyter Notebook or Jupyter Lab.
2. Follow the instructions in the cells to simulate the ransomware attack, detect, and mitigate it.
3. After running the notebooks, you will be able to observe the effects of the ransomware and evaluate the effectiveness of your detection and mitigation strategies.

## Acknowledgments
- Special thanks to all contributors and resources used to develop the concepts in this project.
- References used for building the ransomware defense strategies include [list of references].

## License
This project is licensed under the MIT License – see the LICENSE file for details.
