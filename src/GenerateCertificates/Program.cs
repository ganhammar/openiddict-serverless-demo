var encryption =  GenerateCertificates.GenerateCertificates.EncryptionCertificate();
var signing = GenerateCertificates.GenerateCertificates.SigningCertificate();

Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine("Encryption certificate");
Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine(encryption);
Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine("");
Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine("Signing certificate");
Console.WriteLine("--------------------------------------------------------------------------");
Console.WriteLine(signing);
Console.WriteLine("--------------------------------------------------------------------------");
