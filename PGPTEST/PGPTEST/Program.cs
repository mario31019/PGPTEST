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



namespace PGPTEST
{
    internal class Program
    {


        static void Main(string[] args)
        {
            Program Go = new Program();
            Go.CreateThePAndVKey();//用BouncyCastle的API產出公鑰與私鑰然後生成ASC檔案到D:\BD的資料夾
         
        }
        //=======================create公鑰跟私鑰到D:\BD的資料夾==========================
        public void CreateThePAndVKey()
        {
            //RSA密鑰產生器
            IAsymmetricCipherKeyPairGenerator kpgS = GeneratorUtilities.GetKeyPairGenerator("RSA");
            IAsymmetricCipherKeyPairGenerator kpgR = GeneratorUtilities.GetKeyPairGenerator("RSA");
            //Key 構造使用參數        
            kpgS.Init(new RsaKeyGenerationParameters(
                   BigInteger.ValueOf(0x10001), new SecureRandom(),
            1024,// key 的長度
             25));
            kpgR.Init(new RsaKeyGenerationParameters(
                   BigInteger.ValueOf(0x10001), new SecureRandom(),
            1024,// key 的長度
             25));
            AsymmetricCipherKeyPair kpS = kpgS.GenerateKeyPair();
            AsymmetricCipherKeyPair kpR = kpgR.GenerateKeyPair();
            char[] passwordS = "S123456".ToCharArray(); //私鑰的密碼
            char[] passwordR = "R123456".ToCharArray(); //私鑰的密碼
            Stream out1, out2, out4, out3;
            out1 = File.Create(@"D:\BCB\privS.asc");//傳送方私鑰放置位置          
            out2 = File.Create(@"D:\BCB\pubS.asc"); //傳送方公鑰放置位置
            out3 = File.Create(@"D:\BCB\privR.asc");//接收方私鑰放置位置          
            out4 = File.Create(@"D:\BCB\pubR.asc"); //接收方公鑰放置位置
            ExportKeyPair(out1, out2, kpS.Public,
            kpS.Private, "Sender", passwordS, true);
            ExportKeyPair(out3, out4, kpR.Public,
            kpR.Private, "Receiver", passwordR, true);

        }
        //--------------------------------------------------------------------------------
        //======================輸出公私鑰到指定資料夾以共後續使用========================
        private static void ExportKeyPair(
          Stream secretOut,//私鑰放置位置
          Stream publicOut,//公鑰放置位置
          AsymmetricKeyParameter publicKey,//私鑰
          AsymmetricKeyParameter privateKey,//公鑰
          string identity,//身分
          char[] passPhrase,//密碼
          bool armor)
        {
            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }
            PgpSecretKey secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                PublicKeyAlgorithmTag.RsaGeneral,
                publicKey,
                privateKey,
                DateTime.UtcNow,
                identity,
                SymmetricKeyAlgorithmTag.Cast5,
                passPhrase,
                null,
                null,
                new SecureRandom()
                );
            secretKey.Encode(secretOut);
            if (armor)
            {
                secretOut.Close();
                publicOut = new ArmoredOutputStream(publicOut);
            }
            PgpPublicKey key = secretKey.PublicKey;
            key.Encode(publicOut);
            if (armor)
            {
                publicOut.Close();
            }


        }
        //--------------------------------------------------------------------------------




    }
}
    