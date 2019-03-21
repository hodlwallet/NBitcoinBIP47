using System;

using NBitcoin;
using NBitcoin.DataEncoders;

namespace NBitcoin.BIP47
{
    public enum PaymentCodeVersion {V1 = 0x01, V2 = 0x02}

    public class PaymentCode
    {
        const int PUBLIC_KEY_Y_OFFSET = 2;
        
        const int PUBLIC_KEY_X_OFFSET = 3;
        
        const int CHAIN_OFFSET = 35;
        
        const int PUBLIC_KEY_X_LEN = 32;
        
        const int PUBLIC_KEY_Y_LEN = 1;
        
        const int CHAIN_LEN = 32;
        
        const int PAYLOAD_LEN = 80;

        public const byte V1 = 0x01;

        public const byte V2 = 0x02;

        string _PaymentCodeString = null;

        byte[] _Pubkey = null;

        byte[] _Chain = null;

        byte _Version;

        public PaymentCode(byte[] payload)
        {
            if (payload.Length != 80) throw new ArgumentException("Invalid payload");

            _Pubkey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];
            _Chain = new byte[CHAIN_LEN];

            Array.Copy(payload, PUBLIC_KEY_Y_OFFSET, _Pubkey, 0, PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN);
            Array.Copy(payload, CHAIN_OFFSET, _Chain, 0, CHAIN_LEN);

            _PaymentCodeString = EncodePaymentCodeV1();
        }

        public PaymentCode(byte[] pubkey, byte[] chain)
        {
            if (pubkey.Length != (PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN))
                throw new ArgumentException($"Invalid pubkey {new HexEncoder().EncodeData(pubkey)}");
            
            if (chain.Length != CHAIN_LEN)
                throw new ArgumentException($"Invalid chain {new HexEncoder().EncodeData(chain)}");

            _Pubkey = pubkey;
            _Chain = chain;
        }

        private string EncodePaymentCode(PaymentCodeVersion version)
        {
            if (version != PaymentCodeVersion.V1 || version != PaymentCodeVersion.V2)
                throw new ArgumentException($"Invalid version 0x{((byte) version):X02}");

            byte[] payload = new byte[PAYLOAD_LEN];
            byte[] paymentCode = new byte[PAYLOAD_LEN + 1];

            // TODO: verify if this is needed
            for (int i = 0; i < PAYLOAD_LEN; i++)
            {
                payload[i] = 0x00;
            }

            // Byte 0: type
            payload[0] = (byte) version;

            // Byte 1: Features bit field. All bits must be zero except where specified elsewhere in this specification
            //      Bit 0: Bitmessage notification
            //      Bits 1-7: reserved
            payload[1] = (byte) 0x00;

            // Replace sign & x code (33 bytes)
            Array.Copy(_Pubkey, 0, payload, PUBLIC_KEY_Y_OFFSET, _Pubkey.Length);
            // Replace chain code (32 bytes)
            Array.Copy(_Chain, 0, payload, CHAIN_OFFSET, _Chain.Length);

            // Add prefix byte for BIP47's payment codes
            paymentCode[0] = (byte) 0x47;
            Array.Copy(payload, 0, paymentCode, 1, payload.Length);

            // Append checksum
            return new Base58CheckEncoder().EncodeData(paymentCode);
        }

        private string EncodePaymentCodeV1()
        {
            return EncodePaymentCode(PaymentCodeVersion.V1);
        }

        private string EncodePaymentCodeV2()
        {
            return EncodePaymentCode(PaymentCodeVersion.V2);
        }
    }
}