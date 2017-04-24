using System;
using System.Security.Cryptography;
using System.Text;
using Serilog;
using Extensions;
using System.Net.Http;

namespace WalmartAPI.Classes
{
    public class Authentication
    {
        #region constructors

        public Authentication()
        {
            SetTimestemp();
            SetCorrelationId();
        }
        /// <summary>
        /// Create an authentication object to be used with a request to walmart.com API
        /// </summary>
        /// <param name="consumerId">WalMart provided ConsumerID</param>
        /// <param name="baseUrl">The url for the request to be authenticated</param>
        /// <param name="privateKey">Provided by walmart</param>
        /// <param name="httpRequestMethod">the request method</param>
        /// <param name="channelType">Channel type provided by walmart</param>
        public Authentication(string consumerId,Uri baseUrl,string privateKey, HttpMethod httpRequestMethod,string channelType) : this(consumerId,privateKey)
        {
            //this.consumerId = consumerId;
            this.BaseUrl = baseUrl.AbsoluteUri;
            //this.privateKey = privateKey;
            this.HttpRequestMethod = httpRequestMethod.Method;
            this.ChannelType = channelType;
            SignData();
        }
        public Authentication(string consumerId,string privateKey) : this()
        {
            this.ConsumerId = consumerId;
            this.PrivateKey = privateKey;
        }
        public Authentication(string consumerId,string privateKey,string channelType) : this(consumerId, privateKey)
        {
            this.ChannelType = channelType;
        }
        #endregion

        #region Properties

        public string ConsumerId { get; set; }
        public string BaseUrl { get; set; }
        public string PrivateKey { get; set; }
        public string HttpRequestMethod { get; set; }
        public string TimeStamp { get; set; }
        public string Signature { get; set; }
        public string ChannelType { get; set; }
        public string CorrelationId { get; set; }

        #endregion

        #region Methods

        private void SetTimestemp()
        {
            //set timestemp
            var ts = DateTimeOffset.UtcNow;
            TimeStamp = ts.ToUnixTimeMilliseconds().ToString();
        }
        private void SetCorrelationId()
        {
            CorrelationId = Guid.NewGuid().ToString().Replace("-", "");
        }
        public void SignData()
        {
            Log.Verbose("Begining signData()");
            try
            {
                //set timestemp
                SetTimestemp();

                var strToSign = string.Format("{0}\n{1}\n{2}\n{3}\n", ConsumerId, BaseUrl, HttpRequestMethod, TimeStamp);

                Log.Verbose("string to sign set to {StrToSign}", strToSign);

                //Decoding the Base 64, PKCS - 8 representation of your private key.Note that the key is encoded using PKCS-8. Libraries in various languages offer the ability to specify that the key is in this format and not in other conflicting formats such as PKCS-1.
                var decoded = Convert.FromBase64String(PrivateKey);
                var byteTosign = Encoding.Default.GetBytes(strToSign);

                string signed;
                using (var bb = CngKey.Import(decoded, CngKeyBlobFormat.Pkcs8PrivateBlob))
                {
                    using (var rsa = new RSACng(bb))
                    {
                        //Use this byte representation of your key to sign the data using SHA-256 With RSA.
                        var signedBytes = rsa.SignData(byteTosign, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                        signed = Convert.ToBase64String(signedBytes);
                    }
                }
                //Encode the resulting signature using Base 64.
                Signature = signed;
                Log.Verbose("Signature set to {signature} for {timestemp} and url {url}", Signature,TimeStamp,BaseUrl);
            }
            catch(Exception ex)
            {
                ex.LogWithSerilog();
                throw;
            }
        }
        
        #endregion
    }
}
