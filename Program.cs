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

            ExtKey alicePaymentCodeKey = aliceMasterKey.Derive(new KeyPath("47'/0'/0'"));
            ExtKey bobPaymentCodeKey = bobMasterKey.Derive(new KeyPath("47'/0'/0'"));

            Console.WriteLine($"Alice's payment code priv key: {alicePaymentCodeKey.ToString(Network.Main)}");
            Console.WriteLine($"Bob's payment code priv key: {bobPaymentCodeKey.ToString(Network.Main)}");

            Console.WriteLine($"Version: {PaymentCodeVersion.V1} in bytes: 0x{((byte) PaymentCodeVersion.V1):X02}");
            Console.WriteLine($"Version: {PaymentCodeVersion.V2} in bytes: 0x{((byte) PaymentCodeVersion.V2):X02}");

            ExtPubKey aliceExtPubKey = alicePaymentCodeKey.Neuter();
            PaymentCode alicePC = new PaymentCode(aliceExtPubKey, aliceExtPubKey.ChainCode);
            ExtPubKey bobExtPubKey = bobPaymentCodeKey.Neuter();
            PaymentCode bobPC = new PaymentCode(bobExtPubKey, bobExtPubKey.ChainCode);

            Console.WriteLine($"Alice's payment code: {alicePC.ToString()}");
            Console.WriteLine($"Alice's notification address: {alicePC.NotificationAddress(Network.Main).ToString()}");
            Console.WriteLine($"Bob's payment code: {bobPC.ToString()}");
            Console.WriteLine($"Bob's notification address: {bobPC.NotificationAddress(Network.Main).ToString()}");
        }
    }
}
