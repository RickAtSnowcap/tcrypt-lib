using System.Security.Cryptography;
using System.Text;

namespace Snowcap.TCrypt;

/// <summary>
/// Snowcap TCrypt — AES-256-GCM authenticated string encryption and decryption.
///
/// Format: Base64(nonce + ciphertext + tag)
///   - 12-byte random nonce generated per encryption
///   - AES-256-GCM (AEAD — provides confidentiality + integrity + authenticity)
///   - 16-byte authentication tag appended after ciphertext
///   - 32-byte (256-bit) key required
///
/// This is the standard encryption format for all Snowcap applications.
/// The same key and format are used across C# and Python consumers.
/// </summary>
public static class SuitcaseCrypt
{
    private const int KeyLength = 32;    // AES-256
    private const int NonceLength = 12;  // GCM standard nonce
    private const int TagLength = 16;    // GCM authentication tag

    /// <summary>
    /// Encrypts a plaintext string using AES-256-GCM with a random nonce.
    /// </summary>
    /// <param name="plainText">The string to encrypt.</param>
    /// <param name="key">The 32-byte AES-256 key.</param>
    /// <returns>Base64-encoded string containing nonce + ciphertext + tag.</returns>
    /// <exception cref="ArgumentNullException">Thrown when plainText or key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key length is not 32 bytes.</exception>
    public static string Encrypt(string plainText, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyLength(key);

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceLength);
        byte[] cipherBytes = new byte[plainBytes.Length];
        byte[] tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag);

        // Wire format: nonce[12] + ciphertext[n] + tag[16]
        byte[] result = new byte[NonceLength + cipherBytes.Length + TagLength];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceLength);
        Buffer.BlockCopy(cipherBytes, 0, result, NonceLength, cipherBytes.Length);
        Buffer.BlockCopy(tag, 0, result, NonceLength + cipherBytes.Length, TagLength);

        return Convert.ToBase64String(result);
    }

    /// <summary>
    /// Decrypts a Base64-encoded encrypted string produced by <see cref="Encrypt"/>.
    /// </summary>
    /// <param name="encryptedText">The Base64-encoded string containing nonce + ciphertext + tag.</param>
    /// <param name="key">The 32-byte AES-256 key.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedText or key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when encryptedText is empty or too short, or key length is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (wrong key, corrupted data, or tampered ciphertext).</exception>
    public static string Decrypt(string encryptedText, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encryptedText);
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrWhiteSpace(encryptedText))
            throw new ArgumentException("Encrypted text cannot be empty.", nameof(encryptedText));

        ValidateKeyLength(key);

        byte[] raw = Convert.FromBase64String(encryptedText);

        if (raw.Length < NonceLength + TagLength + 1)
            throw new ArgumentException("Encrypted data is too short to contain a nonce, ciphertext, and tag.", nameof(encryptedText));

        byte[] nonce = raw[..NonceLength];
        byte[] cipherBytes = raw[NonceLength..^TagLength];
        byte[] tag = raw[^TagLength..];
        byte[] plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes);

        return Encoding.UTF8.GetString(plainBytes);
    }

    /// <summary>
    /// Loads the Suitcase key from the systemd credential directory.
    /// The key is delivered by systemd via LoadCredentialEncrypted= after
    /// TPM unsealing at service start. It lives at
    /// $CREDENTIALS_DIRECTORY/{credentialName} and only exists while the
    /// service is running.
    /// </summary>
    /// <param name="credentialName">
    /// Name of the credential (default: "suitcase-key").
    /// Must match the name used in LoadCredentialEncrypted= in the unit file.
    /// </param>
    /// <returns>The 32-byte AES-256 key.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when CREDENTIALS_DIRECTORY is not set (not running under systemd
    /// with LoadCredentialEncrypted=).
    /// </exception>
    /// <exception cref="FileNotFoundException">Thrown when the credential file does not exist.</exception>
    /// <exception cref="ArgumentException">Thrown when the key is not exactly 32 bytes.</exception>
    public static byte[] LoadKey(string credentialName = "suitcase-key")
    {
        var credDir = Environment.GetEnvironmentVariable("CREDENTIALS_DIRECTORY");

        if (string.IsNullOrEmpty(credDir))
            throw new InvalidOperationException(
                "CREDENTIALS_DIRECTORY is not set. This application must run as a systemd service " +
                "with LoadCredentialEncrypted= configured in the unit file.");

        var keyPath = Path.Combine(credDir, credentialName);

        if (!File.Exists(keyPath))
            throw new FileNotFoundException(
                $"Credential '{credentialName}' not found at {keyPath}. " +
                "Verify LoadCredentialEncrypted= is configured in the unit file.",
                keyPath);

        byte[] key = File.ReadAllBytes(keyPath);
        ValidateKeyLength(key);
        return key;
    }

    private static void ValidateKeyLength(byte[] key)
    {
        if (key.Length != KeyLength)
            throw new ArgumentException($"Key must be exactly {KeyLength} bytes for AES-256, got {key.Length} bytes.", nameof(key));
    }
}
