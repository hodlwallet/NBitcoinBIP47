using System;
using System.IO;
using System.Security.Cryptography;

using NBitcoin;
using NBitcoin.DataEncoders;
using NBitcoin.Crypto;
using NBitcoin.BouncyCastle.Security;
using NBitcoin.BouncyCastle.Crypto.Parameters;


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

        const int SAMOURAI_FEATURE_BYTE = 79;
        
        const int SAMOURAI_SEGWIT_BIT = 0;

        string _PaymentCodeString = null;

        string _SamouraiPaymentCodeString = null;

        byte[] _Pubkey = null;

        byte[] _Chain = null;

        byte[] _Payload = null;

        public PaymentCode(byte[] payload)
        {
            if (payload.Length != 80) throw new ArgumentException("Invalid payload");

            _Pubkey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];
            _Chain = new byte[CHAIN_LEN];

            Array.Copy(payload, PUBLIC_KEY_Y_OFFSET, _Pubkey, 0, PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN);
            Array.Copy(payload, CHAIN_OFFSET, _Chain, 0, CHAIN_LEN);

            _PaymentCodeString = EncodePaymentCodeV2();
            _SamouraiPaymentCodeString = EncodeSamouraiPaymentCode();
        }

        public PaymentCode(byte[] pubkey, byte[] chain)
        {
            if (pubkey.Length != (PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN))
                throw new ArgumentException($"Invalid pubkey {new HexEncoder().EncodeData(pubkey)}");
            
            if (chain.Length != CHAIN_LEN)
                throw new ArgumentException($"Invalid chain {new HexEncoder().EncodeData(chain)}");

            _Pubkey = pubkey;
            _Chain = chain;

            _PaymentCodeString = EncodePaymentCodeV2();
            _SamouraiPaymentCodeString = EncodeSamouraiPaymentCode();
        }

        public string EncodePaymentCode(PaymentCodeVersion version)
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
                byte[] pcodeBytes = null;
                string paymentCode = isSamouraiPaymentCode ? _SamouraiPaymentCodeString : _PaymentCodeString;

                if (string.IsNullOrEmpty(paymentCode)) throw new ArgumentNullException($"Payment code '{paymentCode}' is empty!");

                pcodeBytes = new Base58CheckEncoder().DecodeData(paymentCode);

                MemoryStream memoryStream = new MemoryStream(pcodeBytes);

                if(memoryStream.ReadByte() != 0x47)
                {
                    throw new FormatException($"Invalid version in payment code {paymentCode}");
                }
                else
                {
                    byte[] chain = new byte[CHAIN_LEN];
                    byte[] pubkey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];
                    // type:
                    memoryStream.ReadByte();
                    // feature:
                    memoryStream.ReadByte();
                    
                    memoryStream.Read(pubkey);
                    memoryStream.Read(chain);

                    MemoryStream pubkeyMemoryStream = new MemoryStream(pubkey);
                    int firstByte = pubkeyMemoryStream.ReadByte();

                    if(firstByte == 0x02 || firstByte == 0x03){
                        return true;
                    }
                    else {
                        return false;
                    }
                }
            }
            catch (EndOfStreamException)
            {
                return false;
            }
            catch(FormatException)
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

        public static byte[] GetMask(byte[] sPoint, byte[] oPoint) {
            return new HMACSHA512(oPoint).ComputeHash(sPoint);
        }

        public static byte[] Blind(byte[] payload, byte[] mask)
        {
            byte[] ret = new byte[PAYLOAD_LEN];
            byte[] pubkey = new byte[PUBLIC_KEY_X_LEN];
            byte[] chain = new byte[CHAIN_LEN];
            byte[] buf0 = new byte[PUBLIC_KEY_X_LEN];
            byte[] buf1 = new byte[CHAIN_LEN];

            Array.Copy(payload, 0, ret, 0, PAYLOAD_LEN);

            Array.Copy(payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN);
            Array.Copy(payload, CHAIN_OFFSET, chain, 0, CHAIN_LEN);
            Array.Copy(mask, 0, buf0, 0, PUBLIC_KEY_X_LEN);
            Array.Copy(mask, PUBLIC_KEY_X_LEN, buf1, 0, CHAIN_LEN);

            Array.Copy(XOR(pubkey, buf0), 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
            Array.Copy(XOR(chain, buf1), 0, ret, CHAIN_OFFSET, CHAIN_LEN);

            return ret;
        }

        public BitcoinAddress NotificationAddress(Network network)
        {
            return AddressAt(0, network);
        }

        private BitcoinAddress AddressAt(int idx, Network network)
        {
            // TODO: Figure out how to get the addrses from the payment code
            return new Key().PubKey.Hash.GetAddress(network);
        }

        private byte SetBit(byte b, int pos)
        {
            return (byte) (b | (1 << pos));
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

            for(int i = 0; i < a.Length; i++)   {
                ret[i] = (byte)((int)b[i] ^ (int)a[i]);
            }

            return ret;
        }

        private (byte[] Pubkey, byte[] Chain) Parse(bool isSamouraiPaymentCode)
        {
            byte[] pcBytes = new Base58CheckEncoder().DecodeData(isSamouraiPaymentCode ? _SamouraiPaymentCodeString : _PaymentCodeString);

            MemoryStream mem = new MemoryStream(pcBytes);
            if(mem.ReadByte() != 0x47)
                throw new FormatException("Invalid payment code version");

            byte[] chain = new byte[CHAIN_LEN];
            byte[] pubkey = new byte[PUBLIC_KEY_X_LEN + PUBLIC_KEY_Y_LEN];

            // type:
            mem.ReadByte();
            // features:
            mem.ReadByte();

            mem.Read(pubkey);
            
            if (pubkey[0] != 0x02 && pubkey[0] != 0x03)
                throw new FormatException("Invalid public key");

            mem.Read(chain);

            return (pubkey, chain);
        }
    }
}