using Org.BouncyCastle.Bcpg.OpenPgp.Examples;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPTEST3
{
    internal class UnLockTest
    {
        public void UnLockT()
        {
            Debug.WriteLine("====================S檔案解密實作===================");
            string decryptEncryptFileName = @"D:/BCB/LockAndUnSing.txt";//待解密的檔案名稱跟位置
            string keyFileName = @"D:/BCB/privR.asc";//解密用的接收方R私鑰名稱跟位置
            char[] passwd = "R123456".ToCharArray();//接收方R私鑰的密碼
            string defaultFileName = @"D:/BCB/apple2.pdf";//產出的檔案名稱跟位置
            try
            {
                DecryptFile(decryptEncryptFileName, keyFileName,
                        passwd, defaultFileName);
                Console.WriteLine("解密成功");
                Debug.WriteLine("====================E檔案解密實作===================");
            }
            catch (Exception e)
            {
                Console.WriteLine("解密失敗" + e.Message);
            }
        }
        public static void DecryptFile(
        string inputFileName,  //欲解密之檔案名稱及位置
        string keyFileName,    //解密 Private key 位置
        char[] passwd,         //Private key password
        string defaultFileName //解密後檔案名稱及位置
    )
        {
            using (Stream input = File.OpenRead(inputFileName),
                   keyIn = File.OpenRead(keyFileName))
            {
                DecryptFile(input, keyIn, passwd, defaultFileName);
            }
        }

        //內部解密實作參照官方範例
        private static void DecryptFile(
            Stream inputStream,
            Stream keyIn,
            char[] passwd,
            string defaultFileName)
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);

            try
            {
                PgpObjectFactory pgpF = new PgpObjectFactory(inputStream);
                PgpEncryptedDataList enc;

                PgpObject o = pgpF.NextPgpObject();
                //
                // the first object might be a PGP marker packet.
                //
                if (o is PgpEncryptedDataList)
                {
                    enc = (PgpEncryptedDataList)o;
                }
                else
                {
                    enc = (PgpEncryptedDataList)pgpF.NextPgpObject();
                }

                //
                // find the secret key
                //
                PgpPrivateKey sKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(
                    PgpUtilities.GetDecoderStream(keyIn));

                foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
                {
                    sKey = PgpExampleUtilities.FindSecretKey(pgpSec, pked.KeyId, passwd);

                    if (sKey != null)
                    {
                        pbe = pked;
                        break;
                    }
                    
                }

                if (sKey == null)
                {
                    throw new ArgumentException("secret key for message not found.");
                }

                Stream clear = pbe.GetDataStream(sKey);

                PgpObjectFactory plainFact = new PgpObjectFactory(clear);

                PgpObject message = plainFact.NextPgpObject();

                if (message is PgpCompressedData)
                {
                    PgpCompressedData cData = (PgpCompressedData)message;
                    PgpObjectFactory pgpFact = new PgpObjectFactory(cData.GetDataStream());

                    message = pgpFact.NextPgpObject();
                }

                if (message is PgpLiteralData)
                {
                    PgpLiteralData ld = (PgpLiteralData)message;

                    string outFileName = ld.FileName;
                    //if (outFileName.Length == 0)
                    //{
                    outFileName = defaultFileName;
                    //}

                    Stream fOut = File.Create(outFileName);
                    Stream unc = ld.GetInputStream();
                    Streams.PipeAll(unc, fOut);
                    fOut.Close();
                }
                else if (message is PgpOnePassSignatureList)
                {
                    throw new PgpException("encrypted message contains a signed message - not literal data.");
                }
                else
                {
                    throw new PgpException("message is not a simple encrypted file - type unknown.");
                }

                if (pbe.IsIntegrityProtected())
                {
                    if (!pbe.Verify())
                    {
                        Console.Error.WriteLine("message failed integrity check");
                    }
                    else
                    {
                        Console.Error.WriteLine("message integrity check passed");
                    }
                }
                else
                {
                    Console.Error.WriteLine("no message integrity check");
                }
            }
            catch (PgpException e)
            {
                Console.Error.WriteLine(e);
                Console.WriteLine("++++++++++密碼錯誤了+++++++++++++++");
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
