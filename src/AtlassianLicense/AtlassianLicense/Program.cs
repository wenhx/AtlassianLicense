using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AtlassianLicense
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("请输入（空行回车结束输入）：");
            StringBuilder licenceString = new StringBuilder();
            while (true)
            {
                var input = Console.ReadLine();
                licenceString.Append(input);
                if (input == string.Empty)
                    break;
            }
            var result = Version2LicenseDecoder.Verify(licenceString.ToString());
            Console.WriteLine("验证结果：" + result);
        }
    }
}
