using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace EncryptionLayer
{
    public class Session
    {
        private string _Payload { get; set; }
        public string Payload
        {
            get
            {
                return _Payload;
            }
            set
            {
                _Payload = value;
            }
        }

        private string _EncryptedPayload { get; set; }
        public string EncryptedPayload
        {
            get
            {
                return _EncryptedPayload;
            }
            set
            {
                _EncryptedPayload = value;
            }
        }

        private string _Secret { get; set; }
        public string Secret
        {
            get
            {
                return _Secret;
            }
            set
            {
                _Secret = value;
            }
        }

        private byte[] _SecretKey { get; set; }
        public byte[] SecretKey
        {
            get
            {
                return _SecretKey;
            }
            set
            {
                _SecretKey = value;
            }
        }


        public Session(string Payload = "", string Key = "")
        {
            _Payload = Payload;
            _Secret = Key;
        }

        public void Encrypt()
        {
            SecretKey = CreateKey(Secret);
            EncryptedPayload = Encrypt(Payload, SecretKey);
        }

        public override string ToString()
        {
            return string.Format("Plain Text Key: {0}\nPlain Text Message: {1}\nEncrypted Payload: {2}\nEncryption Key: {3}\n", Secret, Payload, EncryptedPayload, SecretKey);
        }

        private static string HashSHA512(string LowerSalt, string Payload, string UpperSalt)
        {
            using(var sha = SHA512.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(LowerSalt + Payload + UpperSalt)));
            }
        }
        private static byte[] CreateKey(string Secret, int KeyBytes = 32, byte[] SaltParam = null)
        {
            byte[] Salt = SaltParam;
            Random RandomSaltCount = new Random();
            Random RandomSaltByte = new Random();
            Random RandomIterationCount = new Random();

            if (Salt == null)
            {
                int Count = RandomSaltCount.Next(8, 100);
                Salt = new byte[Count];

                for(int i = 0; i < Count; i ++)
                {
                    Salt[i] = Convert.ToByte(RandomSaltByte.Next(0, 255));
                }
            }

            int Iterations = RandomIterationCount.Next(0, 1000);

            var Generator = new Rfc2898DeriveBytes(Secret, Salt, Iterations);
            return Generator.GetBytes(KeyBytes);
        }
        private static string Encrypt(string Payload, byte[] EncryptionKey)
        {
            using(Aes aes = Aes.Create())
            {
                aes.Key = EncryptionKey;
                byte[] encrypted = AesEncryptStringTobytes(Payload, aes.Key);
                return Convert.ToBase64String(encrypted) + ";" + Convert.ToBase64String(aes.IV);
            }
        }


        private static byte[] AesEncryptStringTobytes(string Payload, byte[] EncryptionKey, byte[] InitializationVector = null)
        {
            if (Payload == null || Payload.Length <= 0)
                throw new ArgumentNullException($"{nameof(Payload)}");
            if (EncryptionKey == null || EncryptionKey.Length <= 0)
                throw new ArgumentNullException($"{nameof(EncryptionKey)}");
            //if (InitializationVector == null || InitializationVector.Length <= 0)
            //    throw new ArgumentNullException($"{nameof(InitializationVector)}");

            byte[] encrypted;

            using(Aes aes = Aes.Create())
            {
                aes.Key = EncryptionKey;
                //aes.IV = InitializationVector;

                using(MemoryStream MemStream = new MemoryStream())
                {
                    using(ICryptoTransform encryptor = aes.CreateEncryptor())
                    using(CryptoStream cryptoStream = new CryptoStream(MemStream, encryptor, CryptoStreamMode.Write))
                    using(StreamWriter streamWriter = new StreamWriter(cryptoStream))
                    {
                        streamWriter.Write(Payload);
                    }

                    encrypted = MemStream.ToArray();
                }
            }

            return encrypted;
        }
    }
}
