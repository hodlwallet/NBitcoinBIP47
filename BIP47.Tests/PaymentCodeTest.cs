using System;
using Xunit;

using NBitcoin;

namespace NBitcoin.BIP47.Tests
{
    public class PaymentCodeTest
    {
        private Mnemonic _AliceMnemonic = new Mnemonic("response seminar brave tip suit recall often sound stick owner lottery motion");
        private Mnemonic _BobMnemonic = new Mnemonic("reward upper indicate eight swift arch injury crystal super wrestle already dentist");
        private ExtKey _AliceMasterKey;
        private ExtKey _BobMasterKey;
        private PaymentCode _AlicePC;
        private PaymentCode _BobPC;

        public PaymentCodeTest()
        {
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
        public void TestPaymentCodeSrc()
        {
            Assert.Equal(
                "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA",
                _AlicePC.ToString()
            );

            Assert.Equal(
                "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97",
                _BobPC.ToString()
            );
        }

        [Fact]
        public void TestNotificationAddress()
        {
            Assert.Equal("1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW", _AlicePC.NotificationAddress(Network.Main).ToString());
            Assert.Equal("1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV", _BobPC.NotificationAddress(Network.Main).ToString());
        }
    }
}
