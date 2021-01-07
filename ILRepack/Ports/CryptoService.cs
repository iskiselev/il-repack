//
// Author:
//   Jb Evain (jbevain@gmail.com)
//
// Copyright (c) 2008 - 2015 Jb Evain
// Copyright (c) 2008 - 2011 Novell, Inc.
//
// Licensed under the MIT/X11 license.
//

using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Runtime.Serialization;

using Mono.Security.Cryptography;

using Mono.Cecil.PE;

namespace Mono.Cecil
{

    // Most of this code has been adapted
    // from Jeroen Frijters' fantastic work
    // in IKVM.Reflection.Emit. Thanks!

    static class CryptoService
    {

        public static byte[] GetPublicKey(WriterParameters parameters)
        {
            using (var rsa = parameters.CreateRSA())
            {
                var cspBlob = CryptoConvert.ToCapiPublicKeyBlob(rsa);
                var publicKey = new byte[12 + cspBlob.Length];
                Buffer.BlockCopy(cspBlob, 0, publicKey, 12, cspBlob.Length);
                // The first 12 bytes are documented at:
                // http://msdn.microsoft.com/library/en-us/cprefadd/html/grfungethashfromfile.asp
                // ALG_ID - Signature
                publicKey[1] = 36;
                // ALG_ID - Hash
                publicKey[4] = 4;
                publicKey[5] = 128;
                // Length of Public Key (in bytes)
                publicKey[8] = (byte)(cspBlob.Length >> 0);
                publicKey[9] = (byte)(cspBlob.Length >> 8);
                publicKey[10] = (byte)(cspBlob.Length >> 16);
                publicKey[11] = (byte)(cspBlob.Length >> 24);
                return publicKey;
            }
        }
    }

    static partial class Mixin
    {

        public static RSA CreateRSA(this WriterParameters writer_parameters)
        {
            byte[] key;
            string key_container;

            if (writer_parameters.StrongNameKeyBlob != null)
                return CryptoConvert.FromCapiKeyBlob(writer_parameters.StrongNameKeyBlob);

            if (writer_parameters.StrongNameKeyContainer != null)
                key_container = writer_parameters.StrongNameKeyContainer;
            else if (!TryGetKeyContainer(writer_parameters.StrongNameKeyPair, out key, out key_container))
                return CryptoConvert.FromCapiKeyBlob(key);

            var parameters = new CspParameters
            {
                Flags = CspProviderFlags.UseMachineKeyStore,
                KeyContainerName = key_container,
                KeyNumber = 2,
            };

            return new RSACryptoServiceProvider(parameters);
        }

        static bool TryGetKeyContainer(ISerializable key_pair, out byte[] key, out string key_container)
        {
            var info = new SerializationInfo(typeof(StrongNameKeyPair), new FormatterConverter());
            key_pair.GetObjectData(info, new StreamingContext());

            key = (byte[])info.GetValue("_keyPairArray", typeof(byte[]));
            key_container = info.GetString("_keyPairContainer");
            return key_container != null;
        }
    }
}