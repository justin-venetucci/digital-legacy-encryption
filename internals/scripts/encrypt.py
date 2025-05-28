"""
Digital Legacy Encryption Script
Python version of the PowerShell encryption script, designed for long-term compatibility
Companion to decrypt.py using age encryption with Shamir's Secret Sharing
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
READ_TIME = 0.500  # seconds
SPIN_TIME = 2.000  # seconds
# =========================

class EncryptionError(Exception):
    """Custom exception for encryption-related errors"""
    pass

class DigitalLegacyEncryptor:
    def __init__(self):
        # Folder paths
        self.scripts_dir = Path(__file__).parent
        self.internals_dir = self.scripts_dir.parent
        self.binaries_dir = self.internals_dir / "binaries"
        self.encrypted_dir = self.internals_dir / "encrypted"
        self.keys_dir = self.internals_dir / "age-keys-DISTRIBUTE-AND-DELETE"

        # Binary paths
        self.age_path = self.binaries_dir / "age"
        self.age_keygen_path = self.binaries_dir / "age-keygen"
        self.plugin_path = self.binaries_dir / "age-plugin-sss"
        
        # Add .exe extension to binaries on Windows
        if os.name == 'nt':
            self.age_path = self.age_path.with_suffix('.exe')
            self.age_keygen_path = self.age_keygen_path.with_suffix('.exe')
            self.plugin_path = self.plugin_path.with_suffix('.exe')
        
        # Optional paths
        self.ascii_path = self.scripts_dir / "resources" / "ascii.txt"
        self.recipients_config_path = None
        
        # State variables
        self.source_file = None
        self.temp_dir = None
        self.current_step = 1
        self.total_steps = 5
        
        # Environment preparation
        self.env = None  # Will hold the modified environment

    # ------------------ SETUP FUNCTIONS ------------------
    def set_up_paths_and_validation(self):
        """Set up paths and validate required files exist"""
        missing_files = []
        
        if not self.age_path.exists():
            missing_files.append(f"age executable: {self.age_path}")
        if not self.age_keygen_path.exists():
            missing_files.append(f"age-keygen executable: {self.age_keygen_path}")
        if not self.plugin_path.exists():
            missing_files.append(f"age-plugin-sss executable: {self.plugin_path}")
        
        # Find recipients file
        recipients_files = list(self.encrypted_dir.glob("*.yaml"))
        while not recipients_files:
            with open(f"{self.encrypted_dir}/recipients.yaml", "w") as recipients_file:
                lines = ["threshold: ", "shares: ", "  - ", "  - ", "# No config found, created blank config"]
                recipients_file.writelines(line + '\n' for line in lines) #file.write("threshold: \nshares: \n- ")
            recipients_files = list(self.encrypted_dir.glob("*.yaml"))

        if len(recipients_files) > 1:
            missing_files.append(f"Too many recipients yaml files ({len(recipients_files)}) found in 'encrypted' folder")
        else:
            self.recipients_config_path = recipients_files[0]

        # Create encrypted directory if it doesn't exist
        if not self.encrypted_dir.exists():
            self.encrypted_dir.mkdir(parents=True, exist_ok=True)

        if missing_files:
            error_msg = "Missing required files:\n" + "\n".join(f"- {f}" for f in missing_files)
            raise EncryptionError(error_msg)

    def set_up_temp_directory(self):
        """Set up temporary directory for intermediate files"""
        self.temp_dir = Path(tempfile.mkdtemp(prefix="digital_legacy_encrypt_"))

    def cleanup_temp_files(self):
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
        """Display ASCII art if available"""
        if self.ascii_path and self.ascii_path.exists():
            ascii_art = self.ascii_path.read_text(encoding='utf-8')
            self._print_colored(ascii_art, "green")

    def show_step_banner(self, step_title, color="cyan"):
        """Display step banner matching decrypt script format"""
        banner_width = 100
        step_text = f"[Step {self.current_step} of {self.total_steps}] {step_title}"
        
        # Calculate padding
        padding = (banner_width - len(step_text)) // 2
        left_padding = " " * padding
        right_padding = " " * (banner_width - len(step_text) - padding)
        
        # Unicode box-drawing characters
        print()
        self._print_colored("╔" + "═" * banner_width + "╗", color)
        self._print_colored(f"║{left_padding}{step_text}{right_padding}║", color)
        self._print_colored("╚" + "═" * banner_width + "╝", color)
        print()

    def show_processing_step(self, message, success=True, delay=0.5):
        """Show a processing step with result"""
        if delay > 0:
            time.sleep(delay)
        
        if success:
            self._print_colored(f"{message}... Done", "green")
        else:
            self._print_colored(f"{message}... Failed", "red")

    def show_welcome_message(self):
        """Display welcome message with ASCII art"""
        # Clear screen
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Show ASCII art if available
        self.show_ascii_art()
        
        self.show_step_banner("Getting Started")
        
        self._print_colored("This tool will help you encrypt sensitive information securely using", "white")
        self._print_colored("Shamir's Secret Sharing, requiring multiple keys to decrypt.", "white")
        print()
        self._print_colored("You will configure how many keys are needed to unlock this information.", "cyan")
        print()
        self._print_colored("Please follow the prompts to encrypt your information.", "white")
        
        self._print_colored("\nPress Enter to begin...", "magenta")
        input()

    # ------------------ FILE SELECTION FUNCTIONS ------------------
    def get_source_file(self):
        """Get file to encrypt from user using file dialog"""
        self.show_step_banner("Select File to Encrypt")
        
        try:
            self._print_colored("Press Enter to launch the file selection dialog.", "white")
            input()
            
            # Create a temporary root window for the file dialog
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            root.attributes('-topmost', True)  # Ensure dialog appears on top
            
            file_path = filedialog.askopenfilename(
                title="Select File to Encrypt",
                filetypes=[("All Files", "*.*")],
                initialdir=str(Path.home() / "Desktop")
            )
            
            root.destroy()
            
            if not file_path:
                self._print_colored("Error: No file selected. Operation cancelled.", "red")
                raise EncryptionError("No file selected")
            
            # Check if the file has .age extension
            if Path(file_path).suffix == ".age":
                self._print_colored("Error: Cannot encrypt a file that already has a .age extension.", "red")
                raise EncryptionError("File already encrypted")
            
            filename = Path(file_path).name
            self._print_colored(f"You selected: {filename}", "white")
            self.show_processing_step("Validating file", True, 0.5)
            
            return file_path
            
        except Exception as e:
            if "No file selected" in str(e) or "Operation cancelled" in str(e):
                raise
            self._print_colored(f"Error: Could not select file: {e}", "red")
            raise EncryptionError(f"File selection failed: {e}")

    # ------------------ KEY MANAGEMENT FUNCTIONS ------------------
    def get_key_configuration(self):
        """Get key configuration from user"""
        self.current_step += 1
        self.show_step_banner("Configure Encryption Keys")
        
        self._print_colored("How would you like to configure encryption keys?", "white")
        print()
        self._print_colored("1) Generate new recipient identities (creates new key files)", "white")
        self._print_colored("2) Use existing recipients from recipients.yaml", "white")
        
        choice = ""
        while choice not in ["1", "2"]:
            choice = input("\nEnter your choice (1 or 2): ").strip()
            if choice not in ["1", "2"]:
                self._print_colored("Error: Invalid choice. Please enter 1 or 2.", "red")
        
        return choice

    def get_numeric_input(self, prompt, min_val=1, max_val=100):
        """Get and validate numeric input from user"""
        value = 0
        is_valid = False
        
        while not is_valid:
            try:
                user_input = input(prompt).strip()
                
                if user_input.isdigit():
                    value = int(user_input)
                    if min_val <= value <= max_val:
                        is_valid = True
                    else:
                        self._print_colored(f"Error: Please enter a number between {min_val} and {max_val}.", "red")
                else:
                    self._print_colored("Error: Please enter a valid number.", "red")
            except (ValueError, KeyboardInterrupt):
                self._print_colored("Error: Please enter a valid number.", "red")
        
        return value

    def generate_age_key(self):
        """Generate a new age key pair"""
        try:
            process = subprocess.Popen(
                [str(self.age_keygen_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                raise EncryptionError(f"Error generating age key: {stderr}")
            
            # Extract public key from comment line and secret key
            public_key_match = re.search(r'# public key: (age1\S+)', stdout)
            secret_key_match = re.search(r'(AGE-SECRET-KEY-\S+)', stdout)
            
            if not public_key_match:
                raise EncryptionError("Could not extract public key")
            if not secret_key_match:
                raise EncryptionError("Could not extract secret key")
            
            return {
                'public_key': public_key_match.group(1),
                'secret_key': secret_key_match.group(1),
                'key_output': stdout
            }
            
        except subprocess.SubprocessError as e:
            raise EncryptionError(f"Failed to generate age key: {e}")

    def save_key_file(self, key_content, key_name, keys_directory):
        """Save key content to a file"""
        # Create the directory if it doesn't exist
        keys_dir_path = Path(keys_directory)
        keys_dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create the filename
        key_file_path = keys_dir_path / f"Key for Digital Legacy - {key_name}.yaml"
        
        # Write the content to the file
        key_file_path.write_text(key_content, encoding='utf-8')
        
        return str(key_file_path)

    def generate_key_config(self, threshold, public_keys, recipients_config_path):
        """Generate recipients.yaml file"""
        # Check if file exists
        if Path(recipients_config_path).exists():
            self._print_colored("recipients.yaml already exists.", "yellow")
            overwrite = input("Do you want to overwrite it? (y/n): ").strip().lower()
            if not overwrite.startswith('y'):
                self._print_colored("Error: Operation cancelled. Existing recipients.yaml file was not overwritten.", "red")
                raise EncryptionError("File overwrite cancelled")
        
        # Create the content
        config_content = f"threshold: {threshold}\nshares:\n"
        for key in public_keys:
            config_content += f"  - {key}\n"
        
        # Write to file
        Path(recipients_config_path).write_text(config_content, encoding='utf-8')
        
        return recipients_config_path

    def generate_sss_recipient(self, key_config_path):
        """Generate SSS recipient from key configuration"""
        if not Path(key_config_path).exists():
            raise EncryptionError(f"Key configuration file not found at: {key_config_path}")
        
        try:
            process = subprocess.Popen(
                [str(self.plugin_path), "--generate-recipient", key_config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                raise EncryptionError(f"Error generating SSS recipient: {stderr}")
            
            recipient = stdout.strip()
            if not recipient:
                raise EncryptionError("Generated recipient is empty. Please check the key configuration file.")
            
            return recipient
            
        except subprocess.SubprocessError as e:
            raise EncryptionError(f"Failed to generate SSS recipient: {e}")

    def handle_new_key_generation(self):
        """Handle generation of new keys"""
        print()
        # Get number of identities to generate
        num_identities = self.get_numeric_input(
            "How many key files would you like to generate? (1-10): ", 1, 10
        )
        
        # Get threshold
        threshold = self.get_numeric_input(
            f"How many keys should be required to decrypt? (1-{num_identities}): ", 1, num_identities
        )
        
        print()
        self._print_colored(f"Generating {num_identities} keys with threshold of {threshold} required for decryption.", "white")
        
        # Generate key names (you can customize these)
        key_names = []
        for i in range(num_identities):
            name = input(f"Enter name for key {i+1} (or press Enter for 'Key{i+1}'): ").strip()
            if not name:
                name = f"Key{i+1}"
            key_names.append(name)
        
        print()
        self.show_processing_step("Generating encryption keys", True, 1.0)
        
        # Generate the identities
        public_keys = []
        key_files = []
        
        for i, name in enumerate(key_names):
            self.show_processing_step(f"Creating key file for {name}", True, 0.3)
            
            # Generate key
            key_data = self.generate_age_key()
            
            # Save the key file
            key_file = self.save_key_file(key_data['key_output'], name, self.keys_dir)
            key_files.append(key_file)
            
            # Add the public key to our list
            public_keys.append(key_data['public_key'])
        
        # Generate recipients.yaml
        self.show_processing_step("Creating key configuration", True, 0.5)
        config_file = self.generate_key_config(threshold, public_keys, self.recipients_config_path)
        
        print()
        self._print_colored(f"Key files created in: {self.keys_dir}", "green")
        self._print_colored(f"At least {threshold} out of {num_identities} keys will be needed to decrypt.", "dark_yellow")
        
        return self.recipients_config_path

    def handle_existing_keys(self):
        """Handle using existing key configuration"""
        # Check if recipients.yaml exists
        if not Path(self.recipients_config_path).exists():
            self._print_colored("Error: recipients.yaml not found.", "red")
            self._print_colored("Please run the script again and choose to generate new keys.", "white")
            raise EncryptionError("recipients.yaml not found")
        
        self.show_processing_step("Loading existing key configuration", True, 0.5)
        
        # Ask if user wants to modify the config
        modify_config = input("\nWould you like to open the key configuration file to make changes? (y/n): ").strip().lower()
        if modify_config.startswith('y'):
            self.show_processing_step("Opening configuration file", True, 0.3)
            # Open the file
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(self.recipients_config_path)
                elif sys.platform == 'darwin':  # macOS
                    subprocess.run(['open', str(self.recipients_config_path)])
                else:  # Linux/Unix
                    subprocess.run(['xdg-open', str(self.recipients_config_path)])
            except Exception as e:
                self._print_colored(f"Error: Could not open file: {e}", "red")
                self._print_colored(f"Please manually open: {self.recipients_config_path}", "yellow")
            
            # Wait for confirmation
            input("\nPress Enter when you have finished making changes and saved the file: ")
        
        return self.recipients_config_path

    # ------------------ ENCRYPTION FUNCTIONS ------------------
    def encrypt_file(self, source_file, recipient):
        """Encrypt the source file with the given recipient"""
        # Get source filename for output
        source_path = Path(source_file)
        source_filename = source_path.stem
        source_filesuffix = source_path.suffix
        
        # Create timestamped filename
        timestamp = datetime.now().strftime("%Y-%m-%d")
        output_filename = f"{source_filename} - Encrypted {timestamp}{source_filesuffix}.age"
        output_path = self.encrypted_dir / output_filename
        
        # Ensure we don't overwrite an existing file
        counter = 1
        while output_path.exists():
            output_filename = f"[SENSITIVE] {source_filename} - Encrypted {timestamp} ({counter}).age"
            output_path = self.encrypted_dir / output_filename
            counter += 1
        
        try:
            process = subprocess.Popen(
                [str(self.age_path), "-e", "-r", recipient, "-o", str(output_path), source_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=self.env
            )
            
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                raise EncryptionError(f"Encryption failed: {stderr}")
            
            return str(output_path)
            
        except subprocess.SubprocessError as e:
            raise EncryptionError(f"Failed to encrypt file: {e}")

    # ------------------ MAIN EXECUTION FUNCTION ------------------
    def run(self):
        """Main execution function"""
        try:
            # Setup and validation
            self.set_up_paths_and_validation()
            self.set_up_temp_directory()
            self.prepare_environment()
            
            # Step 1: Welcome
            self.show_welcome_message()
            
            # Step 2: Get source file
            self.current_step = 2
            self.source_file = self.get_source_file()
            
            # Step 3: Configure keys
            key_choice = self.get_key_configuration()
            
            # Handle key configuration
            if key_choice == "1":
                recipients_config_path = self.handle_new_key_generation()
            else:
                recipients_config_path = self.handle_existing_keys()
            
            # Step 4: Generate recipient and encrypt
            self.current_step += 1
            self.show_step_banner("Generate Encryption Configuration")
            
            self.show_processing_step("Processing key configuration", True, 1.0)
            sss_recipient = self.generate_sss_recipient(recipients_config_path)
            
            self.show_processing_step("Preparing encryption parameters", True, 0.5)
            
            # Step 5: Encrypt file
            self.current_step += 1
            self.show_step_banner("Encrypt Your Information")
            
            source_filename = Path(self.source_file).name
            self.show_processing_step(f"Encrypting {source_filename}", True, 2.0)
            
            encrypted_path = self.encrypt_file(self.source_file, sss_recipient)
            
            self._print_colored("Your information has been encrypted.", "green")
            print()
            print("The encrypted file has been saved to:")
            self._print_colored(encrypted_path, "white")
            
            # Final step: Success
            self.current_step += 1
            self.show_step_banner("Encryption Complete")
            
            self._print_colored("Encryption completed successfully!", "green")
            print()
            self._print_colored("IMPORTANT REMINDERS:", "yellow")
            self._print_colored("• Distribute the key files securely to trusted individuals", "white")
            self._print_colored("• Keep the recipients.yaml file with your encrypted data", "white")
            self._print_colored("• Test the decryption process to ensure it works", "white")
            
        except EncryptionError as e:
            print()
            self._print_colored(f"Error: {e}", "red")
        except KeyboardInterrupt:
            print()
            self._print_colored("Operation cancelled by user.", "yellow")
        except Exception as e:
            print()
            self._print_colored(f"Unexpected error: {e}", "red")
        finally:
            self.cleanup_temp_files()
            self._print_colored("\nPress Enter to exit...", "magenta")
            input()


def main():
    """Main entry point"""
    encryptor = DigitalLegacyEncryptor()
    encryptor.run()


if __name__ == "__main__":
    main()