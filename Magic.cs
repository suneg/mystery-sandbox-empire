using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Collections.Generic;		

namespace Util.Encryption {
    public class StringCipher
    {
        // This constant is used to determine the keysize of the encryption algorithm.
        private static int ivLength = 16;
        private const int keysize = 256;

        private static void GenerateRandomIv(byte[] iv) {
            RNGCryptoServiceProvider cryptoProvider = new RNGCryptoServiceProvider();
            cryptoProvider.GetBytes(iv);
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
            byte[] iv = new byte[ivLength];

            System.Buffer.BlockCopy(cipherTextBytes, 0, iv, 0, ivLength);

            byte[] cipherTextBytesWithoutIv = new byte[cipherTextBytes.Length - ivLength];
            System.Buffer.BlockCopy(cipherTextBytes, ivLength, cipherTextBytesWithoutIv, 0, cipherTextBytesWithoutIv.Length);

            using(PasswordDeriveBytes password = new PasswordDeriveBytes(passPhrase, null))
            {
                byte[] keyBytes = password.GetBytes(keysize / 8);
                using(AesManaged symmetricKey = new AesManaged())
                {
                    symmetricKey.Mode = CipherMode.CBC;
                    using(ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, iv))
                    {
                        using(MemoryStream memoryStream = new MemoryStream(cipherTextBytesWithoutIv))
                        {
                            using(CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            {
                                byte[] plainTextBytes = new byte[cipherTextBytesWithoutIv.Length];
                                int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                                return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
                            }
                        }
                    }
                }
            }
        }
    }

    public class Bootstrap
    {
        public static void Main(string[] args) 
        {

        	if(args.Length != 1) 
        	{
        		Console.WriteLine("The magic key will unlock the vault!");
        		return;
        	}

        	try 
        	{
	            string challenge = Console.In.ReadToEnd();
	            string password = args[0];

				string decryptedstring = StringCipher.Decrypt(challenge, password);

	            Console.WriteLine(decryptedstring);
        	} catch(Exception ex) 
        	{
        		Console.WriteLine(ex.Message);
        		Console.WriteLine("...hmm.. that doesn't look right.");
        	}
        }
    }
}