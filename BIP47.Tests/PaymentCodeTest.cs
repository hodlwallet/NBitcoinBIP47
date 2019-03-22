using System;
using Xunit;

using NBitcoin;
using NBitcoin.DataEncoders;

namespace NBitcoin.BIP47.Tests
{
    public class PaymentCodeTest
    {
        private Mnemonic _AliceMnemonic;
        private Mnemonic _BobMnemonic;
        private ExtKey _AliceMasterKey;
        private ExtKey _BobMasterKey;
        private PaymentCode _AlicePC;
        private PaymentCode _BobPC;

        public PaymentCodeTest()
        {
            _AliceMnemonic = new Mnemonic("response seminar brave tip suit recall often sound stick owner lottery motion");
            _BobMnemonic = new Mnemonic("reward upper indicate eight swift arch injury crystal super wrestle already dentist");

            _AliceMasterKey = _AliceMnemonic.DeriveExtKey();
            _BobMasterKey = _BobMnemonic.DeriveExtKey();

            _AlicePC = new PaymentCode(_AliceMasterKey);
            _BobPC = new PaymentCode(_BobMasterKey);
        }

        [Fact]
        public void TestVersions()
        {
            Assert.Equal(0x01, (byte) PaymentCodeVersion.V1);
            Assert.Equal(0x02, (byte) PaymentCodeVersion.V2);
        }

        [Fact]
        public void TestV1PaymentCodes()
        {
            Assert.Equal(
                "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
                _AlicePC.ToString()
            );

            Assert.Equal(
                "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97",
                _BobPC.ToString()
            );

            Assert.Equal(
                "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQWfyARm",
                _AlicePC.ToString(IsSamouraiPaymentCode: true)
            );

            Assert.Equal(
                "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisfUMtMJ",
                _BobPC.ToString(IsSamouraiPaymentCode: true)
            );
        }

        [Fact]
        public void TestV2PaymentCodes()
        {
            PaymentCode alicePCV2 = new PaymentCode(_AliceMasterKey, PaymentCodeVersion.V2);
            PaymentCode bobPCV2 = new PaymentCode(_BobMasterKey, PaymentCodeVersion.V2);

            Assert.Equal(
                "PMCbB6zHFpG2aaPB82tKmz2mXJ54dQVbZkzrsmFEFRBsy6AL5Vob3ADn1mXBUBB6maUtXug4jySLqkCyMU4rfhtWFZbwf5dTbE6mmD5gaNLDBVZdz4ZR",
                alicePCV2.ToString()
            );

            Assert.Equal(
                "PMCbB5gHcpvkWfGPAz1QYR7X9jFwYvwc8rJTCK4VAzADbs9DoQUyr2r23aXfTUYtDjunfQcUUwjRWzAKqi4PDzyK2ftyoPAkkFsVQRxHP7PyxxgGunwu",
                bobPCV2.ToString()
            );

            Assert.Equal(
                "PMCbB6zHFpG2aaPB82tKmz2mXJ54dQVbZkzrsmFEFRBsy6AL5Vob3ADn1mXBUBB6maUtXug4jySLqkCyMU4rfhtWFZbwf5dTbE6mmD5gaNLDBVeLBxZz",
                alicePCV2.ToString(IsSamouraiPaymentCode: true)
            );

            Assert.Equal(
                "PMCbB5gHcpvkWfGPAz1QYR7X9jFwYvwc8rJTCK4VAzADbs9DoQUyr2r23aXfTUYtDjunfQcUUwjRWzAKqi4PDzyK2ftyoPAkkFsVQRxHP7PyxxmFszfE",
                bobPCV2.ToString(IsSamouraiPaymentCode: true)
            );
        }

        [Fact]
        public void TestRecoverFromPaymentCode()
        {
            PaymentCode pc = new PaymentCode(_AlicePC.ToString());

            Assert.Equal(_AlicePC.PubKey, pc.PubKey);
            Assert.Equal(_AlicePC.ChainCode, pc.ChainCode);
            Assert.Equal(_AlicePC.Payload, pc.Payload);
            Assert.Equal(_AlicePC.PaymentCodeString, pc.PaymentCodeString);
            Assert.Equal(_AlicePC.PaymentCodeString, pc.PaymentCodeString);
            Assert.Equal(_AlicePC.NotificationAddress(Network.Main), pc.NotificationAddress(Network.Main));
        }

        [Fact]
        public void TestRecoverFromPayload()
        {
            PaymentCode pc = new PaymentCode(_AlicePC.Payload);

            Assert.Equal(_AlicePC.PubKey, pc.PubKey);
            Assert.Equal(_AlicePC.ChainCode, pc.ChainCode);
            Assert.Equal(_AlicePC.Payload, pc.Payload);
            Assert.Equal(_AlicePC.PaymentCodeString, pc.PaymentCodeString);
            Assert.Equal(_AlicePC.PaymentCodeString, pc.PaymentCodeString);
            Assert.Equal(_AlicePC.NotificationAddress(Network.Main), pc.NotificationAddress(Network.Main));
        }

        [Fact]
        public void TestNotificationAddress()
        {
            Assert.Equal("1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW", _AlicePC.NotificationAddress(Network.Main).ToString());
            Assert.Equal("1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV", _BobPC.NotificationAddress(Network.Main).ToString());
        }

        [Fact]
        public void TestIsValid()
        {
            var pc = new PaymentCode("PMCbB6zHFpG2aaPB82tKmz2mXJ54dQVbZkzrsmFEFRBsy6AL5Vob3ADn1mXBUBB6maUtXug4jySLqkCyMU4rfhtWFZbwf5dTbE6mmD5gaNLDBVZdz4ZR");

            Assert.True(pc.IsValid());

            var pcs = new PaymentCode("PMCbB6zHFpG2aaPB82tKmz2mXJ54dQVbZkzrsmFEFRBsy6AL5Vob3ADn1mXBUBB6maUtXug4jySLqkCyMU4rfhtWFZbwf5dTbE6mmD5gaNLDBVeLBxZz");

            Assert.True(pcs.IsValidSamourai());
        }
    }
}
