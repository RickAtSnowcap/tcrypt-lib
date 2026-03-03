# Snowcap TCrypt

AES-256-GCM authenticated encryption library for .NET 10. Native AOT compatible.

## What it does

Encrypts and decrypts strings using AES-256-GCM — an AEAD cipher that provides confidentiality, integrity, and authenticity in a single operation. Each encryption generates a random 12-byte nonce and produces a 16-byte authentication tag. Tampered ciphertext is detected and rejected on decrypt.

**Wire format:** `Base64(nonce[12] + ciphertext[n] + tag[16])`

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

// Decrypt (throws CryptographicException if tampered)
string plaintext = SuitcaseCrypt.Decrypt(encrypted, key);
```

## Cross-language compatibility

The wire format is intentionally simple so any language can produce or consume it:

1. Generate 12 random bytes (nonce)
2. AES-256-GCM encrypt, producing ciphertext + 16-byte auth tag
3. Concatenate `nonce + ciphertext + tag`
4. Base64-encode

Python, Node, Go, or anything else with AES-GCM support can interop with this format using the same key.

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
