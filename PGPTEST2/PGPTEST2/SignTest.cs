using Org.BouncyCastle.Bcpg.OpenPgp.Examples;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGPTEST2
{
    internal class SignTest
    {
        public void SingT() {
            Debug.WriteLine("====================S檔案數位簽章實作===================");
            string fileName = @"D:/BCB/Lock.txt";//等待簽章的檔案名稱與位置
            Stream signkeyIn = File.OpenRead(@"D:/BCB/privS.asc");//簽章用的傳送方S私鑰檔案名稱與位置
            Stream signOutputStream = File.Create(@"D:/BCB/LockAndSing.txt");//輸出簽章後的檔案名稱與位置
            char[] signPass = "S123456".ToCharArray();//簽章用的傳送方S私鑰密碼
            bool signArmor = true;
            bool compress = true;
            try
            {
                SignFile(fileName, signkeyIn, signOutputStream, signPass, signArmor, compress);
                Console.WriteLine("簽章成功");
                Debug.WriteLine("====================E檔案數位簽章實作===================");
            }
            catch (Exception e)
            {
                Console.WriteLine("簽章失敗" + e.Message);
            }
            finally
            {
                signkeyIn.Close();
                signOutputStream.Close();
            }
        }

        private static void SignFile(
                string fileName,        //預作簽章的檔案名稱及位置
                Stream keyIn,       // Private key 的 File Stream
                Stream outputStream,    //簽章後的檔案 File Stream
                char[] pass,        // private Key 的 password
                bool armor,         //用途不明?? 範例預設true
                bool compress       //用途不明?? 範例預設true
    )
        {
            if (armor)
            {
                outputStream = new ArmoredOutputStream(outputStream);
            }
            PgpSecretKey pgpSec = PgpExampleUtilities.ReadSecretKey(keyIn);
            PgpPrivateKey pgpPrivKey = pgpSec.ExtractPrivateKey(pass);
            PgpSignatureGenerator sGen = new PgpSignatureGenerator(pgpSec.PublicKey.Algorithm, HashAlgorithmTag.Sha1);
            sGen.InitSign(PgpSignature.BinaryDocument, pgpPrivKey);
            foreach (string userId in pgpSec.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator spGen = new PgpSignatureSubpacketGenerator();
                spGen.SetSignerUserId(false, userId);
                sGen.SetHashedSubpackets(spGen.Generate());
                // Just the first one!
                break;
            }
            Stream cOut = outputStream;
            PgpCompressedDataGenerator cGen = null;
            if (compress)
            {
                cGen = new PgpCompressedDataGenerator(CompressionAlgorithmTag.ZLib);
                cOut = cGen.Open(cOut);
            }
            BcpgOutputStream bOut = new BcpgOutputStream(cOut);
            sGen.GenerateOnePassVersion(false).Encode(bOut);
            FileInfo file = new FileInfo(fileName);
            PgpLiteralDataGenerator lGen = new PgpLiteralDataGenerator();
            Stream lOut = lGen.Open(bOut, PgpLiteralData.Binary, file);
            FileStream fIn = file.OpenRead();
            int ch = 0;
            while ((ch = fIn.ReadByte()) >= 0)
            {
                lOut.WriteByte((byte)ch);
                sGen.Update((byte)ch);
            }
            fIn.Close();
            lGen.Close();
            sGen.Generate().Encode(bOut);
            if (cGen != null)
            {
                cGen.Close();
            }
            if (armor)
            {
                outputStream.Close();
            }
        }

    }
}
