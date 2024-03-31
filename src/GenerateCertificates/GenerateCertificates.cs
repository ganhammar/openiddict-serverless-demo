using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

    return Convert.ToBase64String(certificate.Export(X509ContentType.Pfx, string.Empty));
  }
}
