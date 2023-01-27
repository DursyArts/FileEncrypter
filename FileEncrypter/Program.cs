using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

class aesCrypto{
    static AesCryptoServiceProvider aesProvider;
    static void ProvideAESKey() {
        aesProvider = new AesCryptoServiceProvider();
        aesProvider.BlockSize = 128;
        aesProvider.KeySize = 256;
        aesProvider.GenerateIV();
        aesProvider.GenerateKey();
        aesProvider.Mode = CipherMode.CBC;
        aesProvider.Padding = PaddingMode.PKCS7;

        File.WriteAllBytes("IV.bin", aesProvider.IV);
        File.WriteAllBytes("Key.bin", aesProvider.Key);
    }

    static public String EncryptData(string data) {
        ICryptoTransform dataEncrypter = aesProvider.CreateEncryptor();

        byte[] encData = dataEncrypter.TransformFinalBlock(ASCIIEncoding.ASCII.GetBytes(data), 0, data.Length);

        string str = Convert.ToBase64String(encData);

        return str;
    }

    static public String DecryptData(string data) {
        ICryptoTransform dataDecrypter = aesProvider.CreateDecryptor();

        byte[] encBytes  = Convert.FromBase64String(data);

        byte[] decData = dataDecrypter.TransformFinalBlock(encBytes, 0, encBytes.Length);

        string str = ASCIIEncoding.ASCII.GetString(decData);

        return str;
    }

    static public int GenerateRSAKeyPair() {
        return 0;
    }

    static void Main() {
        aesCrypto.ProvideAESKey();

        Console.WriteLine(EncryptData("blabla"));

        Console.WriteLine(DecryptData(EncryptData("blabla")));
    }
}