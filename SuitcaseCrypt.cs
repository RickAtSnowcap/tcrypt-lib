using System.Security.Cryptography;
using System.Text;

namespace Snowcap.TCrypt;

/// <summary>
/// Snowcap TCrypt — AES-256-CBC string encryption and decryption.
///
/// Format: Base64(IV + ciphertext)
///   - 16-byte random IV generated per encryption (prepended to ciphertext)
///   - AES-256-CBC with PKCS7 padding
///   - 32-byte (256-bit) key required
///
/// This is the standard encryption format for all Snowcap applications.
/// The same key and format are used across C# and Python consumers.
/// </summary>
public static class SuitcaseCrypt
{
    private const int KeyLength = 32;   // AES-256
    private const int IvLength = 16;    // AES block size

    /// <summary>
    /// Encrypts a plaintext string using AES-256-CBC with a random IV.
    /// </summary>
    /// <param name="plainText">The string to encrypt.</param>
    /// <param name="key">The 32-byte AES-256 key.</param>
    /// <returns>Base64-encoded string containing IV + ciphertext.</returns>
    /// <exception cref="ArgumentNullException">Thrown when plainText or key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when key length is not 32 bytes.</exception>
    public static string Encrypt(string plainText, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(plainText);
        ArgumentNullException.ThrowIfNull(key);
        ValidateKeyLength(key);

        byte[] iv = RandomNumberGenerator.GetBytes(IvLength);
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var encryptor = aes.CreateEncryptor();
        byte[] cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

        byte[] result = new byte[IvLength + cipherBytes.Length];
        Buffer.BlockCopy(iv, 0, result, 0, IvLength);
        Buffer.BlockCopy(cipherBytes, 0, result, IvLength, cipherBytes.Length);

        return Convert.ToBase64String(result);
    }

    /// <summary>
    /// Decrypts a Base64-encoded encrypted string produced by <see cref="Encrypt"/>.
    /// </summary>
    /// <param name="encryptedText">The Base64-encoded string containing IV + ciphertext.</param>
    /// <param name="key">The 32-byte AES-256 key.</param>
    /// <returns>The decrypted plaintext string.</returns>
    /// <exception cref="ArgumentNullException">Thrown when encryptedText or key is null.</exception>
    /// <exception cref="ArgumentException">Thrown when encryptedText is empty or too short, or key length is invalid.</exception>
    /// <exception cref="CryptographicException">Thrown when decryption fails (wrong key, corrupted data).</exception>
    public static string Decrypt(string encryptedText, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(encryptedText);
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrWhiteSpace(encryptedText))
            throw new ArgumentException("Encrypted text cannot be empty.", nameof(encryptedText));

        ValidateKeyLength(key);

        byte[] raw = Convert.FromBase64String(encryptedText);

        if (raw.Length <= IvLength)
            throw new ArgumentException("Encrypted data is too short to contain an IV and ciphertext.", nameof(encryptedText));

        byte[] iv = raw[..IvLength];
        byte[] cipherBytes = raw[IvLength..];

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        byte[] plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

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
