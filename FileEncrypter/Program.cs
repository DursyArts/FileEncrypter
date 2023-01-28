using System;
using System.Security.Cryptography;
using System.IO;
using System.Text;

class aesCrypto{
    static AesCryptoServiceProvider aesProvider;
    static RSACryptoServiceProvider rsaProvider;
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

    /*
    static (RSAParameters PublicKey, RSAParameters PrivateKey) GenerateKey() is the signature of a function called GenerateKey. 
    The static keyword indicates that the function is a class method and can be called without creating an instance of the class. 
    The function is returning a tuple, which is a data structure that can hold multiple values of different types, 
    in this case, it returns two RSAParameters type elements named PublicKey and PrivateKey respectively.
    RSAParameters is a struct that contains the key information for the RSA algorithm. 
    It has several properties such as Modulus, Exponent, P, Q, DP, DQ, InverseQ, and D, that hold the values for the various parameters used in the RSA algorithm.
    The (RSAParameters PublicKey, RSAParameters PrivateKey) part of the function signature is defining the tuple. 
    This means, when the function is called, it will return an object that has two properties PublicKey and PrivateKey which are of type RSAParameters.
    */
    static (RSAParameters PublicKey, RSAParameters PrivateKey) GenerateKey() {
        /*
        In C#, the using keyword is used to create a block of code in which a specific object or resource is acquired and then automatically released when the block of code is exited.
        In the example provided using (var rsa = new RSACryptoServiceProvider(2048)) , it creates an instance of RSACryptoServiceProvider class with a key size of 2048 bits, 
        this object rsa is used to generate the RSA keypair. The using keyword ensures that the rsa object is disposed of properly when the code execution exits the block.
        When the using block is exited, the Dispose method of the rsa object is called. The Dispose method releases any resources held by the object, such as unmanaged memory. 
        This helps to prevent resource leaks and is considered a best practice when working with objects that implement the IDisposable interface.
         */
        //using(rsaProvider = new RSACryptoServiceProvider(2048)) {
        //    /*
        //     * ExportParameters is a method of the RSACryptoServiceProvider class that is used to export the key parameters of an RSA keypair. 
        //     * The method takes a boolean parameter, which indicates whether to export the public or private key parameters. 
        //     * If the parameter is set to false, the method exports the public key parameters, and if it's set to true, it exports the private key parameters.
        //     */

        //    string xmlPub = rsaProvider.ToXmlString(false);
        //    File.WriteAllText("RSApub.xml", xmlPub);
        //    string xmlPri = rsaProvider.ToXmlString(true);
        //    File.WriteAllText("RSApri.xml", xmlPri);
        //    return (rsaProvider.ExportParameters(false), rsaProvider.ExportParameters(true));
        //}

        rsaProvider = new RSACryptoServiceProvider(2048);
        string xmlPub = rsaProvider.ToXmlString(false);
        File.WriteAllText("RSApub.xml", xmlPub);
        string xmlPri = rsaProvider.ToXmlString(true);
        File.WriteAllText("RSApri.xml", xmlPri);

        return (rsaProvider.ExportParameters(false), rsaProvider.ExportParameters(true));
    }

    static (byte[] RSAencryptedAESKey, byte[] RSAencryptedAESIV) EncryptAESKey() {
        byte[] aesKey = aesProvider.Key;
        byte[] aesIV = aesProvider.IV;

        byte[] encryptedAESKey  = rsaProvider.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA1);
        byte[] encryptedAESIV = rsaProvider.Encrypt(aesIV, RSAEncryptionPadding.OaepSHA1);

        rsaProvider.Dispose();

        return (encryptedAESKey, encryptedAESIV);
    }

    static (byte[] DecryptedAESKey, byte[] DecryptedAESIV) DecryptAESKey(byte[] RSAEncryptedAES, byte[] RSAEncryptedIV) {
        string readXMLfile = File.ReadAllText("RSApri.xml"); //Read the Private Key XML file
        rsaProvider = new RSACryptoServiceProvider();

        rsaProvider.FromXmlString(readXMLfile);
        byte[] decryptedAESKey = rsaProvider.Decrypt(RSAEncryptedAES, RSAEncryptionPadding.OaepSHA1);
        byte[] decryptedAESIV = rsaProvider.Decrypt(RSAEncryptedIV, RSAEncryptionPadding.OaepSHA1);

        return (decryptedAESKey, decryptedAESIV);
    }

    static void Main() {
        //Generate the AES Key
        Console.WriteLine("Generating AES Key");
        aesCrypto.ProvideAESKey();

        //Encrypt Data with AES
        string data = "test";
        Console.WriteLine("Encrypting data:\t" + data + " with AES");
        string encryptedData = EncryptData(data);
        Console.WriteLine("Encrypted data:\t" + encryptedData);

        //Generate the RSA Keypair
        Console.WriteLine("Generating RSA Keypair");
        var RSAkey = GenerateKey();

        //Encrypt the AES Key with the public RSA Key
        Console.WriteLine("Encrypting AES Key and IV with RSA Pubkey");
        var RSAEncryptedAES = EncryptAESKey();

        Console.WriteLine("Encrypted AES Key:\t" + Convert.ToBase64String(RSAEncryptedAES.RSAencryptedAESKey) + "\nEncrypted AES IV:\t" + Convert.ToBase64String(RSAEncryptedAES.RSAencryptedAESIV));

        //Send the Keypair to the Server
        // will do later
        //Get Server response (AES Key)
        // will do later
        //Decrypt the data with the returned AES Key that was used to encrypt the data
        // right neow only testing the decrypting method
        var DecryptedAES = DecryptAESKey(RSAEncryptedAES.RSAencryptedAESKey, RSAEncryptedAES.RSAencryptedAESIV);
        Console.WriteLine("Decrypted the AES Key and IV");

        string decryptedData = DecryptData(encryptedData);

        Console.WriteLine("decrypted Data:\t" + decryptedData);
    }
}