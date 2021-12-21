//This project was created for the need of bypassing signature based detection of shellcodes in Process injection exploits
//Disclaimer: Used for educational purposes and security testing only.
//Author: Shaddy43
//Designation: Cybersecurity Engineer, reverse engineer & malware developer


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AES_Encryptor
{
    class Aes_Encryptor
    {

        static string aes_key = "";
        static byte[] aes_iv = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        static void Main(string[] args)
        {
            string file_path = "";
            string output_file = "";

            if (args.Length > 0)
            {
                file_path = args[0];
                output_file = args[1];
                string input_key = args[2];
                aes_key = input_key;

                string hashed = ComputeSha256Hash(aes_key);
                string fixed_hash = hashed.Substring(0, 32);
                aes_key = fixed_hash;

                try
                {
                    byte[] shellcode = File.ReadAllBytes(file_path);
                    Console.WriteLine("Original bytes: " + ByteArrayToString(shellcode));

                    byte[] byte_encrypted = EncryptAES(Convert.ToBase64String(shellcode));
                    string byte_string_encrypted = ByteArrayToString(byte_encrypted);
                    Console.WriteLine("\nEncrypted Bytes: " + byte_string_encrypted);
                    File.WriteAllText(output_file, byte_string_encrypted);

                    String byte_string_decrypted = DecryptAES(byte_encrypted);
                    byte[] byte_decrypted = Convert.FromBase64String(byte_string_decrypted);
                    String byte_encoded = Encoding.UTF8.GetString(byte_decrypted);
                    String display_bytes = ByteArrayToString(byte_decrypted);
                    Console.WriteLine("\nDecrypted String: " + byte_encoded);
                    Console.WriteLine("\nDecrypted Bytes: " + display_bytes);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                }

            }
            else
            {
                Console.WriteLine("No arguements passed!!! \n[1] file path. [2] output file path [3] encryption key \nEg: program.exe shellcode.bin temp.txt mysecretkey");
            }
        }

        static string ComputeSha256Hash(string rawData)
        {
            // Create a SHA256   
            using (SHA256 sha256Hash = SHA256.Create())
            {
                // ComputeHash - returns byte array  
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string   
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);

            for (int i = 0; i < ba.Length-1; i++)
            {
                hex.AppendFormat("0x" + "{0:x2}" + ", ", ba[i]);
            }

            hex.AppendFormat("0x" + "{0:x2}", ba[ba.Length-1]);
            return hex.ToString();
        }

        public static byte[] EncryptAES(string plainText)
        {
            byte[] encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(aes_key);
                aes.IV = aes_iv;

                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform enc = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }

                        encrypted = ms.ToArray();
                    }
                }
            }

            return encrypted;
        }

        public static string DecryptAES(byte[] encrypted)
        {
            string decrypted = null;
            byte[] cipher = encrypted;

            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = Convert.FromBase64String(aes_key);
                //aes.Key = aes_keyy;

                //aes.IV = Convert.FromBase64String(aes_iv);
                aes.IV = aes_iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream ms = new MemoryStream(cipher))
                {
                    using (CryptoStream cs = new CryptoStream(ms, dec, CryptoStreamMode.Read))
                    {
                        using (StreamReader sr = new StreamReader(cs))
                        {
                            decrypted = sr.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }

    }
}
