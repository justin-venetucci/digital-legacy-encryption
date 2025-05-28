"""
Digital Legacy Decryption Script
Python virtual environment-based version of my initial
PowerShell script, designed for for long-term compatibility
Tried my best to make it with with linux / macOS but no gurantees
"""

import os
import sys
import time
import re
import subprocess
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import threading
from tkinter import filedialog, messagebox
import tkinter as tk

# ===== CONFIGURATION =====
READ_TIME = .200  # seconds between message writings
SPIN_TIME = .200  # seconds spent "performing" operations
# =========================

class DecryptionError(Exception):
    """Custom exception for decryption-related errors"""
    pass

class DigitalLegacyDecryptor:
    def __init__(self):
        # Folder paths
        self.scripts_dir = Path(__file__).parent
        self.internals_dir = self.scripts_dir.parent
        self.binaries_dir = self.internals_dir / "binaries"
        self.encrypted_dir = self.internals_dir / "encrypted"
        #self.root_dir = self.internals_dir.parent # no longer used

        # Binary paths
        self.age_path = self.binaries_dir / "age"
        self.age_keygen_path = self.binaries_dir / "age-keygen"
        self.plugin_path = self.binaries_dir / "age-plugin-sss"
        
        # Add .exe extension to binaries on Windows
        if os.name == 'nt':
            self.age_path = self.age_path.with_suffix('.exe')
            self.age_keygen_path = self.age_keygen_path.with_suffix('.exe')
            self.plugin_path = self.plugin_path.with_suffix('.exe')
        
        # Optional paths - must still be declared if not assigned values
        self.ascii_path = self.scripts_dir / "resources" / "ascii.txt"
        self.recipient_config_path = None # formerly self.encrypted_dir / "recipients.yaml"
        self.encrypted_file = None
        self.temp_dir = None # Optional for overriding system temp
        
        # State variables
        self.attempted_keys = {}
        self.key_secrets = []
        self.required_key_count = 0
        self.total_shares = 0
        self.valid_public_keys = []

        # Environment preparation
        self.env = None  # Will hold the modified environment for later use

    # ------------------ SETUP FUNCTIONS ------------------
    def set_up_paths_and_validation(self):
        """Set up paths and validate required files exist"""
        # Check if all required files exist
        missing_files = []
        
        if not self.age_path.exists():
            missing_files.append(f"age executable: {self.age_path}")
        if not self.age_keygen_path.exists():
            missing_files.append(f"age-keygen executable: {self.age_keygen_path}")
        if not self.plugin_path.exists():
            missing_files.append(f"age-plugin-sss executable: {self.plugin_path}")
        
        # Find encrypted file
        encrypted_files = list(self.encrypted_dir.glob("*.age"))
        if not encrypted_files:
            missing_files.append("No encrypted file found in 'encrypted' folder")
        elif len(encrypted_files) > 1:
            missing_files.append(f"Too many encrypted files ({len(encrypted_files)}) found in 'encrypted' folder")
        else:
            self.encrypted_file = encrypted_files[0]
        
        # Find recipients file
        recipients_files = list(self.encrypted_dir.glob("*.yaml"))
        if not recipients_files:
            missing_files.append("No recipients yaml file found in 'encrypted' folder")
        elif len(recipients_files) > 1:
            missing_files.append(f"Too many recipients yaml files ({len(recipients_files)}) found in 'encrypted' folder")
        else:
            self.recipient_config_path = recipients_files[0]

        if missing_files:
            error_msg = "Missing required files:\n" + "\n".join(f"- {f}" for f in missing_files)
            raise DecryptionError(error_msg)

    def set_up_temp_directory(self):
        """Set up temporary directory for intermediate files"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="digital_legacy_"))

    def cleanup_temp_files(self): # not in order of calling but grouping with above
        """Remove temporary files"""
        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def prepare_environment(self):
        """
        Prepares a temporary environment with binaries added to PATH.
        Stores it in self.env for use in subprocess calls later.
        """
        # Copy the current environment
        env = os.environ.copy()

        # Prepend the binaries path to the PATH variable
        env["PATH"] = str(self.binaries_dir) + os.pathsep + env.get("PATH", "")

        # Store the modified environment for later use
        self.env = env

    # ------------------ USER INTERFACE FUNCTIONS ------------------
    def wait_for_keypress(self, prompt="Press Enter to continue..."):
        """Wait for user to press Enter"""
        self._print_colored(f"\n{prompt}", "magenta")
        input()

    def _print_colored(self, text, color="white"):
        """Print colored text to console"""
        colors = {
            'red': '\033[91m',
            'green': '\033[92m',
            'yellow': '\033[93m',
            'blue': '\033[94m',
            'magenta': '\033[95m',
            'cyan': '\033[96m',
            'white': '\033[97m',
            'dark_yellow': '\033[33m',
            'dark_cyan': '\033[36m'
        }
        
        color_code = colors.get(color.lower(), colors['white'])
        reset_code = '\033[0m'
        print(f"{color_code}{text}{reset_code}")

    def show_ascii_art(self):
        if self.ascii_path and self.ascii_path.exists():
            ascii_art = self.ascii_path.read_text(encoding='utf-8')
            self._print_colored(ascii_art, "green")

    def show_banner_message(self, banner_message="Hello World", color="cyan", banner_size=100):
        """Display a banner message with Unicode box-drawing characters"""
        message_length = len(banner_message)
        if message_length >= (banner_size - 2):
            raise ValueError("Banner message too long for specified banner size")
        
        message_odd = message_length % 2
        banner_odd = banner_size % 2
        extra_space = " " if message_odd != banner_odd else ""
        
        spaces_per_side = (banner_size - message_length) // 2
        space_chars = " " * spaces_per_side
        
        # Unicode box-drawing characters
        top_left = "╔"
        top_right = "╗"
        bottom_left = "╚"
        bottom_right = "╝"
        horizontal = "═"
        vertical = "║"
        
        horizontal_line = horizontal * banner_size
        
        print()
        self._print_colored(f"{top_left}{horizontal_line}{top_right}", color)
        self._print_colored(f"{vertical}{space_chars}{extra_space}{banner_message}{space_chars}{vertical}", color)
        self._print_colored(f"{bottom_left}{horizontal_line}{bottom_right}", color)

    def show_spinner(self, message="Processing", duration=1.0, success=True):
        """Display a spinner animation"""
        symbols = ['|', '/', '-', '\\']
        symbol_index = 0
        start_time = time.time()
        
        print()
        while time.time() - start_time < duration:
            print(f"\r{message} {symbols[symbol_index]}", end='', flush=True)
            time.sleep(0.1)
            symbol_index = (symbol_index + 1) % len(symbols)
        
        if success:
            self._print_colored(f"\r{message} Done", "green")
        else:
            self._print_colored(f"\r{message} Failed", "red")


    # ------------------ KEY EXTRACTION FUNCTIONS ------------------
    def get_recipient_config(self):
        """Extract recipient configuration from config file"""
        if not self.recipient_config_path.exists():
            raise DecryptionError(f"Config file not found at: {self.recipient_config_path}")
        
        config_content = self.recipient_config_path.read_text(encoding='utf-8')
        
        # Extract threshold
        threshold_match = re.search(r'threshold:\s*(\d+)', config_content)
        if not threshold_match:
            raise DecryptionError("Unable to find threshold value in config file")
        
        threshold = int(threshold_match.group(1))
        
        # Extract recipient public keys
        shares_match = re.search(r'shares:\s*\n((?:\s*-\s*age1.*\n?)+)', config_content)
        if not shares_match:
            raise DecryptionError("Unable to find shares in config file")
        
        shares_content = shares_match.group(1)
        public_keys = []
        for line in shares_content.split('\n'):
            key_match = re.search(r'-\s*(age1\S+)', line)
            if key_match:
                public_keys.append(key_match.group(1))
        
        return {
            'threshold': threshold,
            'total_shares': len(public_keys),
            'recipient_public_keys': public_keys
        }

    def get_key_file_from_user(self, current_key_number):
        """Get key file path from user using file dialog"""
        try:
            # Create a temporary root window for the file dialog
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            root.attributes('-topmost', True)  # Ensure dialog appears on top
            
            print(f"\nPress Enter to launch the file selection dialog for key {current_key_number}.")
            #print("Remember to click back into this window once you are done selecting...") # TODO: remove
            input()  # Wait for user to press Enter
            
            file_path = filedialog.askopenfilename(
                title=f"Select Key File Number {current_key_number}",
                filetypes=[("Key Files", "*.yaml"), ("All Files", "*.*")],
                initialdir=str(self.scripts_dir.parent / "keys")  # Adjust as needed
            )
            
            root.destroy()
            
            if not file_path:
                raise DecryptionError("No key file selected.")
            
            return file_path
            
        except Exception as e:
            raise DecryptionError(f"Error selecting file: {e}")

    def test_key_path_already_attempted(self, key_path):
        """Check if a key path has already been attempted"""
        if key_path in self.attempted_keys:
            result = "accepted" if self.attempted_keys[key_path] else "declined"
            raise DecryptionError(f"This file has already been {result}. Please select a different one.")

    def test_secret_key_format(self, key_content):
        """Test if content contains a valid secret key format"""
        return bool(re.search(r'^(AGE-SECRET-KEY-[A-Z0-9]+)$', key_content, re.MULTILINE))

    def get_secret_key_from_file(self, key_path):
        """Extract secret key from file"""
        try:
            key_content = Path(key_path).read_text(encoding='utf-8')
        except Exception as e:
            raise DecryptionError(f"Error reading key file: {e}")
        
        if not self.test_secret_key_format(key_content):
            raise DecryptionError("Invalid secret key format. Expected: AGE-SECRET-KEY-XXXXX")
        
        match = re.search(r'^(AGE-SECRET-KEY-[A-Z0-9]+)$', key_content, re.MULTILINE)
        return match.group(1) if match else None

    def get_public_key_from_secret(self, secret_key):
        """Derive public key from secret key using age-keygen"""
        if not self.age_keygen_path.exists():
            raise DecryptionError(f"age-keygen executable not found at: {self.age_keygen_path}")
        
        try:
            process = subprocess.Popen(
                [str(self.age_keygen_path), "-y"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate(input=secret_key)
            
            if "malformed secret key" in stderr or "failed to parse" in stderr:
                raise DecryptionError("Could not derive a valid age public key from the secret. It may have been altered.")
            
            if process.returncode != 0:
                raise DecryptionError(f"Error validating secret key: {stderr}")
            
            public_key = stdout.strip()
            if not self.test_public_key_format(public_key):
                raise DecryptionError("Generated public key doesn't match expected format.")
            
            return public_key
            
        except subprocess.SubprocessError as e:
            raise DecryptionError(f"Error running age-keygen: {e}")

    def test_public_key_format(self, public_key):
        """Test if public key matches expected format"""
        return bool(re.match(r'^age1[a-z0-9]+$', public_key))

    def test_key_usage_for_file(self, public_key):
        """Test if public key was used to encrypt the file"""
        if public_key not in self.valid_public_keys:
            raise DecryptionError("This key was not one of the keys used to encrypt the file.")

    def get_shamir_identity(self, key_secrets_array):
        """Generate Shamir identity from provided decryption secrets"""
        # Create decryption secrets file for age-plugin-sss
        decryption_secrets_path = self.temp_dir / "decryption_secrets.yaml"
        decryption_secrets_content = "identities:\n"
        for key in key_secrets_array:
            decryption_secrets_content += f"  - {key}\n"
        
        decryption_secrets_path.write_text(decryption_secrets_content, encoding='utf-8')
        
        try:
            process = subprocess.Popen(
                [str(self.plugin_path), "--generate-identity", str(decryption_secrets_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate()
            
            if not stdout:
                raise DecryptionError("Failed to generate combined identity from keys.")
            
            if process.returncode != 0:
                raise DecryptionError(f"Error generating Shamir identity: {stderr}")
            
            # Save identity to file
            identity_path = self.temp_dir / "shamir_identity.yaml"
            identity_path.write_text(stdout, encoding='utf-8')
            
            return str(identity_path)
            
        except subprocess.SubprocessError as e:
            raise DecryptionError(f"Error running age-plugin-sss: {e}")

    def save_decrypted_file(self, source_file, identity_file):
        """Decrypt and save the file"""
        # Get the source filename without .age extension
        source_path = Path(source_file)
        source_name_no_age = source_path.stem
        
        # Get base filename and extension
        base_name = Path(source_name_no_age).stem
        extension = Path(source_name_no_age).suffix
        
        if not extension:
            extension = ".bin"
            base_name = source_name_no_age
        
        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d")
        
        # Create output filename
        desktop = Path.home() / "Desktop"
        output_filename = f"[SENSITIVE] {base_name} - Decrypted {timestamp}{extension}"
        output_path = desktop / output_filename
        
        # Ensure we don't overwrite existing files
        counter = 1
        while output_path.exists():
            output_filename = f"[SENSITIVE] {base_name} - Decrypted {timestamp} ({counter}){extension}"
            output_path = desktop / output_filename
            counter += 1
        
        try:
            process = subprocess.Popen(
                [str(self.age_path), "-d", "-i", identity_file, "-o", str(output_path), source_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate()
            
            if "no identity matched any of the recipients" in stderr:
                if output_path.exists():
                    output_path.unlink()
                raise DecryptionError("Decryption failed. No valid identity was found to decrypt the file. Please ensure you have the correct key files.")
            
            if process.returncode != 0:
                raise DecryptionError(f"Error decrypting file: {stderr}")
            
            return str(output_path)
            
        except subprocess.SubprocessError as e:
            raise DecryptionError(f"Error running age: {e}")

    def run(self):
        """Main execution function"""
        try:
            # Setup and validation
            self.set_up_paths_and_validation()
            self.set_up_temp_directory()
            self.prepare_environment()
            
            # Load recipient configuration
            config = self.get_recipient_config()
            self.valid_public_keys = config['recipient_public_keys']
            self.required_key_count = config['threshold']
            self.total_shares = config['total_shares']
            
            # Calculate total steps
            total_steps = self.required_key_count + 3
            current_step = 1
            
            # Clear screen
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Show ASCII art if available
            self.show_ascii_art()
            
            # Step 1 - Getting Started
            self.show_banner_message(f"[Step {current_step} of {total_steps}] Getting Started")
            current_step += 1
            
            print("\nThis tool will help you access sensitive information that has been securely encrypted.")
            self._print_colored(f"\nYou will need {self.required_key_count} out of {self.total_shares} total key files to unlock this information.", "dark_cyan")
            print("\nPlease follow the prompts to select each key file when requested.")
            
            self.wait_for_keypress("Press Enter to begin...")
            
            # Collect key files
            valid_key_count = 0
            current_key_number = 1
            
            while valid_key_count < self.required_key_count:
                try:
                    self.show_banner_message(f"[Step {current_step} of {total_steps}] Upload Key Number {current_key_number}")
                    
                    # Get key file from user
                    try:
                        key_path = self.get_key_file_from_user(current_key_number)
                        key_name = Path(key_path).name
                        print(f"\nYou uploaded: {key_name}")
                    except DecryptionError as e:
                        self.show_spinner("Loading file...", SPIN_TIME, False)
                        self._print_colored(f"\nError: {e}", "red")
                        retry = input("\nWould you like to try again? (y/n): ").strip().lower()
                        if retry in ['y', 'yes']:
                            continue
                        raise DecryptionError("You terminated the program")
                    
                    # Check if already attempted
                    try:
                        self.test_key_path_already_attempted(key_path)
                        self.show_spinner("Loading file...", SPIN_TIME, True)
                    except DecryptionError as e:
                        self.show_spinner("Loading file...", SPIN_TIME, False)
                        self._print_colored(f"\nError: {e}", "red")
                        continue
                    
                    # Extract secret key
                    try:
                        secret_key = self.get_secret_key_from_file(key_path)
                        self.show_spinner("Extracting secret key...", SPIN_TIME, True)
                    except DecryptionError as e:
                        self.show_spinner("Extracting secret key...", SPIN_TIME, False)
                        self._print_colored(f"\nError: {e}", "red")
                        self.attempted_keys[key_path] = False
                        continue
                    
                    # Validate key
                    try:
                        public_key = self.get_public_key_from_secret(secret_key)
                        self.test_key_usage_for_file(public_key)
                        self.show_spinner("Validating secret key...", SPIN_TIME, True)
                        time.sleep(READ_TIME)
                    except DecryptionError as e:
                        self.show_spinner("Validating secret key...", SPIN_TIME, False)
                        self._print_colored(f"\nError: {e}", "red")
                        self._print_colored("Please select a different key.", "dark_yellow")
                        self.attempted_keys[key_path] = False
                        continue
                    
                    # Key accepted
                    self.key_secrets.append(secret_key)
                    valid_key_count += 1
                    remaining_keys = self.required_key_count - valid_key_count
                    
                    self._print_colored("\nKey accepted.", "green")
                    time.sleep(READ_TIME)
                    
                    if remaining_keys > 0:
                        plural = "s" if remaining_keys != 1 else ""
                        print(f"\nYou need {remaining_keys} more key{plural} to unlock your information.")
                        current_key_number += 1
                    else:
                        self._print_colored("\nAll required keys have been provided!", "green")
                    
                    self.attempted_keys[key_path] = True
                    current_step += 1
                    time.sleep(READ_TIME)
                    
                except DecryptionError as e:
                    self._print_colored(f"\nUnexpected error during key processing: {e}", "red")
                    self._print_colored("Please try again.", "dark_yellow")
            
            # Step - Decryption
            self.show_banner_message(f"[Step {current_step} of {total_steps}] Send For Decryption")
            current_step += 1
            
            # Generate Shamir identity
            try:
                identity_path = self.get_shamir_identity(self.key_secrets)
                self.show_spinner("Processing keys...", SPIN_TIME * 2, True)
            except DecryptionError as e:
                self.show_spinner("Processing keys...", SPIN_TIME * 2, False)
                raise
            
            # Decrypt the file
            try:
                decrypted_path = self.save_decrypted_file(str(self.encrypted_file), identity_path)
                self.show_spinner("Decrypting your information...", SPIN_TIME * 4, True)
            except DecryptionError as e:
                self.show_spinner("Decrypting your information...", SPIN_TIME * 4, False)
                raise
            
            # Success message
            self._print_colored("\nYour information has been decrypted.", "green")
            print("\nThe decrypted file has been saved to:")
            print(decrypted_path)
            
            # Step - View File
            self.show_banner_message(f"[Step {total_steps} of {total_steps}] View Decrypted File")
            
            # Ask if user wants to open the file
            open_file = input("\nWould you like to open the file now? (y/n): ").strip().lower()
            if open_file in ['y', 'yes']:
                try:
                    if os.name == 'nt':  # Windows
                        os.startfile(decrypted_path)
                    elif sys.platform == 'darwin':  # macOS
                        subprocess.run(['open', decrypted_path])
                    else:  # Linux/Unix
                        subprocess.run(['xdg-open', decrypted_path])
                except Exception as e:
                    self._print_colored(f"Error opening file: {e}", "red")
                    print(f"Please manually open: {decrypted_path}")
            
        except DecryptionError as e:
            self._print_colored(f"\nError: {e}", "red")
        except KeyboardInterrupt:
            self._print_colored("\nOperation cancelled by user.", "yellow")
        except Exception as e:
            self._print_colored(f"\nUnexpected error: {e}", "red")
        finally:
            self.cleanup_temp_files()
            self.wait_for_keypress("Press Enter to exit...")


def main():
    """Main entry point"""
    decryptor = DigitalLegacyDecryptor()
    decryptor.run()


if __name__ == "__main__":
    main()
