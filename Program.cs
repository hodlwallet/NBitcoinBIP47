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
            Mnemonic mnemonic = new Mnemonic("response seminar brave tip suit recall often sound stick owner lottery motion");
            ExtKey masterKey = mnemonic.DeriveExtKey();
            byte[] seed = mnemonic.DeriveSeed();

            Console.WriteLine($"Mnemonic: {mnemonic.ToString()}");
            Console.WriteLine($"Seed: {new HexEncoder().EncodeData(seed)}");
            Console.WriteLine($"Master key: {masterKey.ToString(Network.Main)}");

            ExtKey paymentCodeKey = masterKey.Derive(new KeyPath("47'/0'/0'"));

            Console.WriteLine($"Derived key for the payment code is: {paymentCodeKey.ToString(Network.Main)}");

            Console.WriteLine(new string('*', 80));

            Console.WriteLine("\nPayment Code Demo\n");

            Console.WriteLine($"Version: {PaymentCodeVersion.V1} in bytes: 0x{((byte) PaymentCodeVersion.V1):X02}");
            Console.WriteLine($"Version: {PaymentCodeVersion.V2} in bytes: 0x{((byte) PaymentCodeVersion.V2):X02}");

            ExtPubKey extPubKey = paymentCodeKey.Neuter();
            PaymentCode pc = new PaymentCode(extPubKey, extPubKey.ChainCode);

            Console.WriteLine($"Payment code: {pc.ToString()}");
            Console.WriteLine($"Notification address: {pc.NotificationAddress(Network.Main).ToString()}");
        }
    }
}
