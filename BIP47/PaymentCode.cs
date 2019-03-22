using System;
using System.IO;
using System.Security.Cryptography;

using NBitcoin.DataEncoders;

namespace NBitcoin.BIP47
{
    public enum PaymentCodeVersion { V1 = 0x01, V2 = 0x02 }

    public class PaymentCode
    {
        const int PUBLIC_KEY_Y_OFFSET = 2;

        const int PUBLIC_KEY_X_OFFSET = 3;

        const int CHAIN_OFFSET = 35;

        const int PUBLIC_KEY_X_LEN = 32;

        const int PUBLIC_KEY_Y_LEN = 1;

        const int CHAIN_CODE_LEN = 32;

        const int PAYLOAD_LEN = 80;

        const int SAMOURAI_FEATURE_BYTE = 79;

        const int SAMOURAI_SEGWIT_BIT = 0;

        string _PaymentCodeString = null;

        string _SamouraiPaymentCodeString = null;

        byte[] _PubKey = null;

        byte[] _ChainCode = null;

        byte[] _Payload = null;

        public PaymentCode()
        {
            _ChainCode = null;
            _PubKey = null;
            _PaymentCodeString = null;
            _SamouraiPaymentCodeString = null;
        }

        public PaymentCode(byte[] pubKey, byte[] chainCode, PaymentCodeVersion version = PaymentCodeVersion.V1)
        {
            if (pubKey.Length != (PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN))
                throw new ArgumentException($"Invalid pubkey {new HexEncoder().EncodeData(pubKey)}");

            if (chainCode.Length != CHAIN_CODE_LEN)
                throw new ArgumentException($"Invalid chain {new HexEncoder().EncodeData(chainCode)}");

            _PubKey = pubKey;
            _ChainCode = chainCode;
           
            _PaymentCodeString = EncodePaymentCode(version);
            _SamouraiPaymentCodeString = EncodeSamouraiPaymentCode();
        }

        public PaymentCode(PubKey pubKey, byte[] chainCode, PaymentCodeVersion version = PaymentCodeVersion.V1) : this(pubKey.ToBytes(), chainCode, version) { }
        public PaymentCode(ExtPubKey extPubKey, byte[] chainCode, PaymentCodeVersion version = PaymentCodeVersion.V1) : this(extPubKey.PubKey, chainCode, version) { }
        public PaymentCode(ExtKey extKey, PaymentCodeVersion version = PaymentCodeVersion.V1) : this(extKey.Derive(new KeyPath("47'/0'/0'")).Neuter(), extKey.Derive(new KeyPath("47'/0'/0'")).ChainCode, version) { }

        public PaymentCode(byte[] payload, PaymentCodeVersion version = PaymentCodeVersion.V1)
        {
            if (payload.Length != 80) throw new ArgumentException("Invalid payload");

            _PubKey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];
            _ChainCode = new byte[CHAIN_CODE_LEN];

            Array.Copy(payload, PUBLIC_KEY_Y_OFFSET, _PubKey, 0, PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN);
            Array.Copy(payload, CHAIN_OFFSET, _ChainCode, 0, CHAIN_CODE_LEN);

            _PaymentCodeString = EncodePaymentCode(version);
            _SamouraiPaymentCodeString = EncodeSamouraiPaymentCode();
        }


        public PaymentCode(string paymentCodeString)
        {
            _PaymentCodeString = paymentCodeString;

            _PubKey = Parse().PubKey;
            _ChainCode = Parse().ChainCode;
        }

        public string EncodePaymentCode(PaymentCodeVersion version)
        {
            if (version != PaymentCodeVersion.V1 && version != PaymentCodeVersion.V2)
                throw new ArgumentException($"Invalid version 0x{((byte)version):X02}");

            byte[] payload = new byte[PAYLOAD_LEN];
            byte[] paymentCode = new byte[PAYLOAD_LEN + 1];

            for (int i = 0; i < PAYLOAD_LEN; i++)
            {
                payload[i] = 0x00;
            }

            // Byte 0: type
            payload[0] = (byte)version;

            // Byte 1: Features bit field. All bits must be zero except where specified elsewhere in this specification
            //      Bit 0: Bitmessage notification
            //      Bits 1-7: reserved
            payload[1] = (byte)0x00;

            // Replace sign & x code (33 bytes)
            Array.Copy(_PubKey, 0, payload, PUBLIC_KEY_Y_OFFSET, _PubKey.Length);
            // Replace chain code (32 bytes)
            Array.Copy(_ChainCode, 0, payload, CHAIN_OFFSET, _ChainCode.Length);

            // Add prefix byte for BIP47's payment codes
            paymentCode[0] = (byte)0x47;
            _Payload = new byte[payload.Length];

            Array.Copy(payload, 0, paymentCode, 1, payload.Length);
            Array.Copy(payload, _Payload, _Payload.Length);

            // Append checksum
            return new Base58CheckEncoder().EncodeData(paymentCode);
        }

        public string EncodeSamouraiPaymentCode()
        {
            byte[] payloadBytes = new byte[_Payload.Length];
            Array.Copy(_Payload, payloadBytes, _Payload.Length);

            // set bit0 = 1 in 'Samourai byte' for segwit. Can send/receive P2PKH, P2SH-P2WPKH, P2WPKH (bech32)
            payloadBytes[SAMOURAI_FEATURE_BYTE] = SetBit(_Payload[SAMOURAI_FEATURE_BYTE], SAMOURAI_SEGWIT_BIT);

            byte[] paymentCode = new byte[PAYLOAD_LEN + 1];

            // add version byte
            paymentCode[0] = (byte)0x47;

            Array.Copy(payloadBytes, 0, paymentCode, 1, payloadBytes.Length);

            // append checksum
            return new Base58CheckEncoder().EncodeData(paymentCode);
        }

        public bool IsValid(bool isSamouraiPaymentCode = false)
        {
            try
            {
                byte[] paymentCodeBytes = null;
                string paymentCodeString = isSamouraiPaymentCode ? _SamouraiPaymentCodeString : _PaymentCodeString;

                if (string.IsNullOrEmpty(paymentCodeString)) throw new ArgumentNullException($"Payment code '{paymentCodeString}' is empty!");

                paymentCodeBytes = new Base58CheckEncoder().DecodeData(paymentCodeString);

                MemoryStream memoryStream = new MemoryStream(paymentCodeBytes);

                if (memoryStream.ReadByte() != 0x47)
                {
                    throw new FormatException($"Invalid version in payment code {paymentCodeString}");
                }
                else
                {
                    byte[] chainCode = new byte[CHAIN_CODE_LEN];
                    byte[] pubKey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];
                    // type:
                    memoryStream.ReadByte();
                    // feature:
                    memoryStream.ReadByte();

                    memoryStream.Read(pubKey);
                    memoryStream.Read(chainCode);

                    MemoryStream pubkeyMemoryStream = new MemoryStream(pubKey);
                    int firstByte = pubkeyMemoryStream.ReadByte();

                    if (firstByte == 0x02 || firstByte == 0x03)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
            }
            catch (EndOfStreamException)
            {
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static byte[] XORMask(byte[] dataToMask64bytes, ISecret secretPoint, OutPoint outPoint)
        {
            PubKey sharedPubKey = secretPoint.PrivateKey.PubKey.GetSharedPubkey(secretPoint.PrivateKey);
            byte[] outpoint = outPoint.ToBytes();

            byte[] mask = GetMask(sharedPubKey.ToBytes(), outpoint);

            return XOR(dataToMask64bytes, mask);
        }

        public static byte[] GetMask(byte[] sPoint, byte[] oPoint)
        {
            return new HMACSHA512(oPoint).ComputeHash(sPoint);
        }

        public static byte[] Blind(byte[] payload, byte[] mask)
        {
            byte[] blindData = new byte[PAYLOAD_LEN];
            byte[] pubKey = new byte[PUBLIC_KEY_X_LEN];
            byte[] chainCode = new byte[CHAIN_CODE_LEN];
            byte[] pubKeyBuf = new byte[PUBLIC_KEY_X_LEN];
            byte[] chainCodeBuf = new byte[CHAIN_CODE_LEN];

            Array.Copy(payload, 0, blindData, 0, PAYLOAD_LEN);

            Array.Copy(payload, PUBLIC_KEY_X_OFFSET, pubKey, 0, PUBLIC_KEY_X_LEN);
            Array.Copy(payload, CHAIN_OFFSET, chainCode, 0, CHAIN_CODE_LEN);
            Array.Copy(mask, 0, pubKeyBuf, 0, PUBLIC_KEY_X_LEN);
            Array.Copy(mask, PUBLIC_KEY_X_LEN, chainCodeBuf, 0, CHAIN_CODE_LEN);

            Array.Copy(XOR(pubKey, pubKeyBuf), 0, blindData, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
            Array.Copy(XOR(chainCode, chainCodeBuf), 0, blindData, CHAIN_OFFSET, CHAIN_CODE_LEN);

            return blindData;
        }

        public BitcoinAddress NotificationAddress(Network network)
        {
            return AddressAt(0, network);
        }

        public string ToString(bool IsSamouraiPaymentCode = false)
        {
            return IsSamouraiPaymentCode ? _SamouraiPaymentCodeString : _PaymentCodeString;
        }

        private BitcoinAddress AddressAt(int idx, Network network)
        {
            ExtPubKey PubKey = new ExtPubKey(new PubKey(_PubKey), _ChainCode);

            return PubKey.Derive(0).PubKey.GetAddress(network);
        }

        private byte SetBit(byte b, int pos)
        {
            return (byte)(b | (1 << pos));
        }

        private string EncodePaymentCodeV1()
        {
            return EncodePaymentCode(PaymentCodeVersion.V1);
        }

        private string EncodePaymentCodeV2()
        {
            return EncodePaymentCode(PaymentCodeVersion.V2);
        }

        private static byte[] XOR(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException($"Invalid length for xor: {a.Length}  vs {b.Length}");

            byte[] ret = new byte[a.Length];

            for (int i = 0; i < a.Length; i++)
            {
                ret[i] = (byte)((int)b[i] ^ (int)a[i]);
            }

            return ret;
        }

        private (byte[] PubKey, byte[] ChainCode) Parse(bool isSamouraiPaymentCode = false)
        {
            byte[] pcBytes = new Base58CheckEncoder().DecodeData(isSamouraiPaymentCode ? _SamouraiPaymentCodeString : _PaymentCodeString);

            MemoryStream mem = new MemoryStream(pcBytes);
            if (mem.ReadByte() != 0x47)
                throw new FormatException("Invalid payment code version");

            byte[] chainCode = new byte[CHAIN_CODE_LEN];
            byte[] pubKey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];

            // type:
            mem.ReadByte();
            // features:
            mem.ReadByte();

            mem.Read(pubKey);

            if (pubKey[0] != 0x02 && pubKey[0] != 0x03)
                throw new FormatException("Invalid public key");

            mem.Read(chainCode);

            return (pubKey, chainCode);
        }
    }
}