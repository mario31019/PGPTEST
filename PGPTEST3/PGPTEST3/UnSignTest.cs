using Org.BouncyCastle.Bcpg.OpenPgp;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPTEST3
{
    internal class UnSignTest
    {
        public void UnSignT() {
            Debug.WriteLine("====================檔案數位認證實作===================");
            Stream inputStream = File.OpenRead(@"D:/BCB/LockAndSing.txt");//等待認證檔案名稱與位置
            Stream keyIn = File.OpenRead(@"D:/BCB/pubS.asc");//認證用的傳送方S公鑰名稱與位置
            string outputFileName = @"D:/BCB/LockAndUnSing.txt";//輸出的檔案名稱與位置
            try
            {
                VerifyFile(inputStream, keyIn, outputFileName);
                Console.WriteLine("認證OK");
            }
            catch (Exception e)
            {
                Console.WriteLine("認證失敗" + e.Message);
            }
        }
        private static void VerifyFile(
                    Stream inputStream,     //準備做數位認證檔案的 File Stream 
                    Stream keyIn,       // Public Key 的 File Stream
                    string outputFileName   // 將數位簽章清除後產生未簽章之原始黨
            )
        {
            inputStream = PgpUtilities.GetDecoderStream(inputStream);
            PgpObjectFactory pgpFact = new PgpObjectFactory(inputStream);
            PgpCompressedData c1 = (PgpCompressedData)pgpFact.NextPgpObject();
            pgpFact = new PgpObjectFactory(c1.GetDataStream());
            PgpOnePassSignatureList p1 = (PgpOnePassSignatureList)pgpFact.NextPgpObject();
            PgpOnePassSignature ops = p1[0];
            PgpLiteralData p2 = (PgpLiteralData)pgpFact.NextPgpObject();
            Stream dIn = p2.GetInputStream();
            PgpPublicKeyRingBundle pgpRing = new PgpPublicKeyRingBundle(PgpUtilities.GetDecoderStream(keyIn));
            PgpPublicKey key = pgpRing.GetPublicKey(ops.KeyId);
            //add
            Stream fileOutput = File.Create(outputFileName);
            ops.InitVerify(key);
            int ch;
            while ((ch = dIn.ReadByte()) >= 0)
            {
                ops.Update((byte)ch);
                fileOutput.WriteByte((byte)ch);
            }
            fileOutput.Close();

            PgpSignatureList p3 = (PgpSignatureList)pgpFact.NextPgpObject();
            PgpSignature firstSig = p3[0];
            if (ops.Verify(firstSig))
            {
                Console.Out.WriteLine("signature verified.");
            }
            else
            {
                Console.Out.WriteLine("signature verification failed.");
            }
        }

    }
}
