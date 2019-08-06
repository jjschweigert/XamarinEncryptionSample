using EncryptionLayer;
using System;

namespace EncryptionPlayground
{
    class Program
    {
        static void Main(string[] args)
        {
            Session session = new Session("poop", "gjenkinsgjenkinsgjenkinsgjenkins");
            session.Encrypt();

            Console.WriteLine(session.ToString());
        }
    }
}
