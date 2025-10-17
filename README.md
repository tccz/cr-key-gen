# "Challenge-Response" Key File Generator for KeePass Databases

A Python utility to generate a "virtual" challenge-response key file from a KeePass database and secret key. If the original YubiKey or OnlyKey used to secure a KeePassXD (or Strongbox / KeePassium etc. database) is lost, this utility can restore access through a keyfile. It implements the Go utility ([keepassxc-cr-recovery](https://github.com/keepassxreboot/keepassxc/tree/develop/utils/keepassxc-cr-recovery)) in Python.

## Description

This tool extracts the Argon2 salt from a KeePass database (KDBX v4+) and combines it with a user-provided secret to generate a HMAC-SHA1 hash, simulating a YubiKey Challenge-Response operation.

## Requirements

- Python 3.6 or higher
- KeePass database file (KDBX version 4 or higher)
- Secret key used during YubiKey Challenge-Response setup

## Installation

Clone the repository:

```bash
git clone https://github.com/tccz/cr-key-gen.git
cd cr-key-gen
```

## Usage

Run the script with your KeePass database file as an argument:

```bash
python3 keyfile.py path/to/your/database.kdbx
```

The script will:

1. Extract the Argon2 salt from the database
2. Prompt for your YubiKey setup secret
3. Generate a key file (`restored.key`)

### Input Formats

The secret can be provided in two formats:

- ASCII text (will be converted to hex)
- Hex string (base16 encoded, no delimiters)

Maximum secret length: 64 bytes

## Output

The script generates a file named `restored.key` containing the HMAC-SHA1 hash that can be used in place of a physical YubiKey or OnlyKey to access the keepass database.

## Error Handling

The script validates:

- KeePass database signature
- Database version compatibility
- Secret length and format
- Salt presence and format

## License

Since the programme logic is adapted on the KeePassXC project, it is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.en.html).

## Security Note

This tool is for development and testing purposes, and to restore access to a keepass database secured with a challenge-response mechanism (YubiKey or OnlyKey). For production use, a physical YubiKey is recommended for better security.
