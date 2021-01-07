//
// Copyright (c) 2015 Francois Valdy
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
using Mono.Cecil;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace ILRepacking.Steps
{
    class SigningStep : IRepackStep
    {
        public class SigningInfo
        {
            public SigningInfo(StrongNameKeyPair keyPair)
            {
                KeyPair = keyPair;
            }
            
            public SigningInfo(byte[] keyBlob)
            {
                KeyBlob = keyBlob;
            }

            public StrongNameKeyPair KeyPair { get; private set; }
            public byte[] KeyBlob { get; private set; }
        }

        readonly IRepackContext _repackContext;
        readonly RepackOptions _repackOptions;

        public SigningInfo KeyInfo { get; private set; }

        public SigningStep(
            IRepackContext repackContext,
            RepackOptions repackOptions)
        {
            _repackContext = repackContext;
            _repackOptions = repackOptions;
        }

        public void Perform()
        {
            if (_repackOptions.KeyContainer != null || (_repackOptions.KeyFile != null && File.Exists(_repackOptions.KeyFile)))
            {
                var publicKey = default(byte[]);
                if (_repackOptions.KeyContainer != null)
                {
                    StrongNameKeyPair snkp = new StrongNameKeyPair(_repackOptions.KeyContainer);
                    publicKey = snkp.PublicKey;
                    if (!_repackOptions.DelaySign)
                        KeyInfo = new SigningInfo(snkp);
                }
                else if(_repackOptions.KeyFile != null && File.Exists(_repackOptions.KeyFile))
                {
                    var keyFileContents = File.ReadAllBytes(_repackOptions.KeyFile);
                    publicKey = CryptoService.GetPublicKey(new WriterParameters { StrongNameKeyBlob = keyFileContents });
                    if (!_repackOptions.DelaySign)
                    {
                        KeyInfo = new SigningInfo(keyFileContents);
                    }
                }
                _repackContext.TargetAssemblyDefinition.Name.PublicKey = publicKey;
                _repackContext.TargetAssemblyDefinition.Name.Attributes |= AssemblyAttributes.PublicKey;
                _repackContext.TargetAssemblyMainModule.Attributes |= ModuleAttributes.StrongNameSigned;
            }
            else
            {
                _repackContext.TargetAssemblyDefinition.Name.PublicKey = null;
                _repackContext.TargetAssemblyMainModule.Attributes &= ~ModuleAttributes.StrongNameSigned;
            }
        }
    }
}
