using Org.BouncyCastle.Bcpg.OpenPgp.Examples;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPTEST2
{
    internal class LockTest
    {
        public void LockT() {
            Debug.WriteLine("====================檔案加密實作===================");
            //Public 1 檔案加密
            string encryptFileName = @"D:/BCB/Lock.pdf";//輸出加密後的檔案名稱跟位置
            string inputFileName = @"D:/BCB/apple.pdf";//要加密的檔案名稱跟位置
            string encKeyFileName = @"D:/BCB/pubR.asc";//加密用的接收方R公鑰名稱跟位置
            bool armor = true;
            bool withIntegrityCheck = false;
            try
            {
                EncryptFile(encryptFileName, inputFileName,
                       encKeyFileName, armor, withIntegrityCheck);
                Console.WriteLine("加密成功");

            }
            catch (Exception e)
            {
                Console.WriteLine("加密失敗" + e.Message);
            }
        }

        //=====================================================================================
        //檔案加密
        public static void EncryptFile(
         string outputFileName,//加密後輸出檔案名稱位置
         string inputFileName, //欲加密檔案名稱位置
         string encKeyFileName,//提供加密的 public key 檔名及位置
         bool armor,           //不明???，範例預設為true
         bool withIntegrityCheck//不明???，範例預設為false
         )
        {
            PgpPublicKey encKey = PgpExampleUtilities.ReadPublicKey(encKeyFileName);

            using (Stream output = File.Create(outputFileName))
            {
                EncryptFile(output, inputFileName, encKey, armor, withIntegrityCheck);
            }
        }

        //內部的實作參照官方範例
        private static void EncryptFile(
            Stream outputStream,
            string fileName,
            PgpPublicKey encKey,
            bool armor,
            bool withIntegrityCheck)
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }

            try
            {
                byte[] bytes = PgpExampleUtilities.CompressFile(fileName, CompressionAlgorithmTag.Zip);

                PgpEncryptedDataGenerator encGen = new PgpEncryptedDataGenerator(
                    SymmetricKeyAlgorithmTag.Cast5, withIntegrityCheck, new SecureRandom());
                encGen.AddMethod(encKey);

                Stream cOut = encGen.Open(outputStream, bytes.Length);

                cOut.Write(bytes, 0, bytes.Length);
                cOut.Close();

                if (armor)
                {
                    outputStream.Close();
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);

                Exception underlyingException = e.InnerException;
                if (underlyingException != null)
                {
                    Console.Error.WriteLine(underlyingException.Message);
                    Console.Error.WriteLine(underlyingException.StackTrace);
                }
            }
        }
    }
}
