using ICSharpCode.SharpZipLib.Zip.Compression.Streams;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace AtlassianLicense
{
    public sealed class Version2LicenseDecoder
    {
        public const string PublicKey = "MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBAIvfweZvmGo5otwawI3no7Udanxal3hX2haw962KL/nHQrnC4FG2PvUFf34OecSK1KtHDPQoSQ+DHrfdf6vKUJphw0Kn3gXm4LS8VK/LrY7on/wh2iUobS2XlhuIqEc5mLAUu9Hd+1qxsQkQ50d0lzKrnDqPsM0WA9htkdJJw2nS";
        public static bool Verify(string licenseString)
        {
            if (string.IsNullOrEmpty(licenseString) || !CanDecode(licenseString))
                return false;

            byte[] licenseData = Convert.FromBase64String(GetLicenceContent(licenseString));
            Console.WriteLine(Encoding.GetEncoding("UTF-32BE").GetString(licenseData.Take(4).ToArray()));
            var length = (((licenseData[0] & 0xff) << 24) | ((licenseData[1] & 0xff) << 16) | ((licenseData[2] & 0xff) << 8) | (licenseData[3] & 0xff));
            var license = licenseData.Skip(4).Take(length).ToArray();
            var sign = licenseData.Skip(length + 4).ToArray();
            byte[] unzipedData;
            using (MemoryStream inStream = new MemoryStream(license.Skip(5).ToArray()))
            using (InflaterInputStream zip = new InflaterInputStream(inStream))
            using (MemoryStream outStream = new MemoryStream())
            {
                zip.CopyTo(outStream);
                unzipedData = outStream.ToArray();
            }
            Console.WriteLine(Encoding.ASCII.GetString(unzipedData));
            return VerifyDsaMessage(Convert.FromBase64String(PublicKey), license, ConvertToP1363Signature(sign));
        }
        static bool VerifyDsaMessage(byte[] keyData, byte[] message, byte[] signature)
        {
            // Load the Public Key X.509 Format
            AsnKeyParser keyParser = new AsnKeyParser(keyData);
            DSAParameters publicKey = keyParser.ParseDSAPublicKey();
            CspParameters csp = new CspParameters();
            // Cannot use PROV_DSS_DH
            const int PROV_DSS = 3;
            csp.ProviderType = PROV_DSS;
            const int AT_SIGNATURE = 2;
            csp.KeyNumber = AT_SIGNATURE;
            csp.KeyContainerName = "DSA Test (OK to Delete)";
            DSACryptoServiceProvider dsa = new DSACryptoServiceProvider(csp);
            dsa.PersistKeyInCsp = false;
            dsa.ImportParameters(publicKey);
            SHA1 sha = new SHA1CryptoServiceProvider();
            byte[] hash = sha.ComputeHash(message);
            DSASignatureDeformatter verifier = new DSASignatureDeformatter(dsa);
            verifier.SetHashAlgorithm("SHA1");
            bool result = verifier.VerifySignature(hash, signature);
            // See http://blogs.msdn.com/tess/archive/2007/10/31/
            //   asp-net-crash-system-security-cryptography-cryptographicexception.aspx
            dsa.Clear();
            return result;
        }
        static bool CanDecode(string licenseString)
        {
            try
            {
                int index = licenseString.LastIndexOf('X');
                if ((index == -1) || (index + 3 >= licenseString.Length))
                    return false;
                int version = int.Parse(licenseString.Substring(index + 1, 2));
                if ((version != 1) && (version != 2))
                    return false;
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        static string GetLicenceContent(string license)
        {
            var lengthStr = license.Substring(license.LastIndexOf('X') + 3);
            var length = ToInt32(lengthStr);
            return license.Substring(0, length);
        }
        static readonly string _Dict = "0123456789abcdefghijklmnopqrstuvwxyz";
        static int ToInt32(string intStr)
        {
            return intStr.Aggregate(0, (sum, c) => sum * 31 + _Dict.IndexOf(c));
        }
        static byte[] ConvertToP1363Signature(byte[] ASN1Sig)
        {
            AsnParser asn = new AsnParser(ASN1Sig);
            asn.NextSequence();
            byte[] r = asn.NextInteger();
            byte[] s = asn.NextInteger();

            // Returned to caller
            byte[] p1363Signature = new byte[40];

            if (r.Length > 21 || (r.Length == 21 && r[0] != 0))
            {
                // WTF???
                // Reject - signature verification failed
            }
            else if (r.Length == 21)
            {
                // r[0] = 0
                // r[1]'s high bit *should* be set
                Array.Copy(r, 1, p1363Signature, 0, 20);
            }
            else if (r.Length == 20)
            {
                // r[0]'s high bit *should not* be set
                Array.Copy(r, 0, p1363Signature, 0, 20);
            }
            else
            {
                // fewer than 20 bytes
                int len = r.Length;
                int off = 20 - len;
                Array.Copy(r, 0, p1363Signature, off, len);
            }

            if (s.Length > 21 || (s.Length == 21 && s[0] != 0))
            {
                // WTF???
                // Reject - signature verification failed
            }
            else if (s.Length == 21)
            {
                // s[0] = 0
                // s[1]'s high bit *should* be set
                Array.Copy(s, 1, p1363Signature, 20, 20);
            }
            else if (s.Length == 20)
            {
                // s[0]'s high bit *should not* be set
                Array.Copy(s, 0, p1363Signature, 20, 20);
            }
            else
            {
                // fewer than 20 bytes
                int len = s.Length;
                int off = 40 - len;
                Array.Copy(s, 0, p1363Signature, off, len);
            }

            return p1363Signature;
        }
    }
}
