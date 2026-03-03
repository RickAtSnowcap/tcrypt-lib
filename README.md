# Snowcap TCrypt

AES-256-CBC string encryption library for .NET 10. Native AOT compatible.

## What it does

Encrypts and decrypts strings using AES-256-CBC with PKCS7 padding. Each encryption generates a random 16-byte IV that is prepended to the ciphertext and Base64-encoded. The same encrypted format is used across C# and Python consumers in Snowcap applications.

**Wire format:** `Base64(IV + ciphertext)`

## Key delivery: the Suitcase pattern

TCrypt includes a `LoadKey()` method that reads the 32-byte AES key from systemd's credential directory. The key is TPM-sealed and delivered to the process at service start via `LoadCredentialEncrypted=` in the unit file. The key only exists in memory while the service is running — it is never on disk in cleartext.

```ini
# systemd unit file excerpt
[Service]
LoadCredentialEncrypted=suitcase-key:/etc/credstore.encrypted/suitcase-key
```

## Usage

```csharp
using Snowcap.TCrypt;

// Load key from systemd credential (production)
byte[] key = SuitcaseCrypt.LoadKey();

// Or bring your own 32-byte key (development/testing)
byte[] key = Convert.FromBase64String("your-base64-key-here");

// Encrypt
string encrypted = SuitcaseCrypt.Encrypt("sensitive data", key);

// Decrypt
string plaintext = SuitcaseCrypt.Decrypt(encrypted, key);
```

## Cross-language compatibility

The wire format is intentionally simple so any language can produce or consume it:

1. Generate 16 random bytes (IV)
2. AES-256-CBC encrypt with PKCS7 padding
3. Concatenate `IV + ciphertext`
4. Base64-encode

Python, Node, Go, or anything else with AES-CBC support can interop with this format using the same key.

## Project reference

```xml
<ProjectReference Include="../tcrypt-lib/TcryptLib.csproj" />
```

## Requirements

- .NET 10
- `IsAotCompatible: true` — no reflection, no dynamic code generation
- For `LoadKey()`: Linux with systemd and TPM 2.0

## License

MIT
