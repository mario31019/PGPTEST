// See https://aka.ms/new-console-template for more information
using System;
using System.Diagnostics;
using System.Security.Policy;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Bcpg.OpenPgp.Examples;
using Org.BouncyCastle.Utilities.IO;
using PGPTEST2;
class Go {
    static void Main(string[] args)
    {
        LockTest aaa = new LockTest();

        aaa.LockT();//加密
        SignTest sss = new SignTest();
        sss.SingT();//簽章
        Console.Read();
    }

}

