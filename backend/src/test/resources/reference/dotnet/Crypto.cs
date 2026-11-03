using System.Net;
using System.Security.Cryptography;

public class Crypto
{
    public byte[] Hash(byte[] data)
    {
        using var md5 = MD5.Create();
        return md5.ComputeHash(data);
    }

    public void Legacy()
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
    }
}
