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
using PGPTEST3;

class goo {
    static void Main() {
        UnSignTest uuu = new UnSignTest();
        //uuu.UnSignT();//認證
        UnLockTest aaa = new UnLockTest();

        aaa.UnLockT();//解密
        Console.Read();
    }
}

