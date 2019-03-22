using System;

using NBitcoin;
using NBitcoin.DataEncoders;

using NBitcoin.BIP47;

namespace NBitcoinBIP47
{
    class Program
    {
        static void Main(string[] args)
        {
            Mnemonic aliceMnemonic = new Mnemonic("response seminar brave tip suit recall often sound stick owner lottery motion");
            Mnemonic bobMnemonic = new Mnemonic("reward upper indicate eight swift arch injury crystal super wrestle already dentist");

            ExtKey aliceMasterKey = aliceMnemonic.DeriveExtKey();
            byte[] aliceSeed = aliceMnemonic.DeriveSeed();
            ExtKey bobMasterKey = bobMnemonic.DeriveExtKey();
            byte[] bobSeed = bobMnemonic.DeriveSeed();

            Console.WriteLine($"Version: {PaymentCodeVersion.V1} in bytes: 0x{((byte) PaymentCodeVersion.V1):X02}");
            Console.WriteLine($"Version: {PaymentCodeVersion.V2} in bytes: 0x{((byte) PaymentCodeVersion.V2):X02}");

            PaymentCode alicePC = new PaymentCode(aliceMasterKey);
            PaymentCode bobPC = new PaymentCode(bobMasterKey);

            Console.WriteLine($"Alice's payment code: {alicePC.ToString()}");
            Console.WriteLine($"Alice's notification address: {alicePC.NotificationAddress(Network.Main).ToString()}");
            Console.WriteLine($"Bob's payment code: {bobPC.ToString()}");
            Console.WriteLine($"Bob's notification address: {bobPC.NotificationAddress(Network.Main).ToString()}");
        }
    }
}
