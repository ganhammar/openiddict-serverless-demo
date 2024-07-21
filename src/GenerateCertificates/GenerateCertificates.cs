using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GenerateCertificates;

public static class GenerateCertificates
{
  public static string SigningCertificate()
    => GenerateCertificate("OpenIddictServerlessDemo Signing Certificate", X509KeyUsageFlags.DigitalSignature);

  public static string EncryptionCertificate()
    => GenerateCertificate("OpenIddictServerlessDemo Encryption Certificate", X509KeyUsageFlags.KeyEncipherment);

  private static string GenerateCertificate(string name, X509KeyUsageFlags usageFlag)
  {
    using var algorithm = RSA.Create(keySizeInBits: 2048);

    var subject = new X500DistinguishedName($"CN={name}");
    var request = new CertificateRequest(subject, algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlag, critical: true));

    var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(2));

    // Export the certificate and private key as PEM
    var certPem = ExportCertificatePem(certificate);
    var privateKeyPem = ExportPrivateKeyPem(algorithm);

    // Combine the certificate and private key into a single PEM string
    return certPem + privateKeyPem;
  }

  private static string ExportCertificatePem(X509Certificate2 certificate)
  {
    var builder = new StringBuilder();
    builder.AppendLine("-----BEGIN CERTIFICATE-----");
    builder.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
    builder.AppendLine("-----END CERTIFICATE-----");
    return builder.ToString();
  }

  private static string ExportPrivateKeyPem(RSA rsa)
  {
    var builder = new StringBuilder();
    var privateKeyBytes = rsa.ExportRSAPrivateKey();
    builder.AppendLine("-----BEGIN RSA PRIVATE KEY-----");
    builder.AppendLine(Convert.ToBase64String(privateKeyBytes, Base64FormattingOptions.InsertLineBreaks));
    builder.AppendLine("-----END RSA PRIVATE KEY-----");
    return builder.ToString();
  }
}