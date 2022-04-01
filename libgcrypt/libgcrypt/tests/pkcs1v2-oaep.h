/* pkcs1v2-oaep.h - OAEP test vector table
 * Copyright 2011 Free Software Foundation, Inc.
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Manually created from the OAEP file in
   ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2-vec.zip
 */

  static struct {
    const char *desc;
    const char *n, *e, *d;
    struct {
      const char *desc;
      const char *mesg;
      const char *seed;
      const char *encr;
    } m[6];
  } tbl[] = {
    {
      "Example 1: A 1024-bit RSA key pair",
      "a8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0ab"
      "c4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72"
      "f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb514"
      "8ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb",
      "010001",
      "53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd"
      "8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55"
      "fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbf"
      "b78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1",
      {
        {
          "OAEP Example 1.1",
          "6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34",
          "18b776ea21069d69776a33e96bad48e1dda0a5ef",
          "354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb"
          "21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535f"
          "a9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426"
          "d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a"
        },{
          "OAEP Example 1.2",
          "750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5",
          "0cc742ce4a9b7f32f951bcb251efd925fe4fe35f",
          "640db1acc58e0568fe5407e5f9b701dff8c3c91e716c536fc7fcec6cb5b71c11"
          "65988d4a279e1577d730fc7a29932e3f00c81515236d8d8e31017a7a09df4352"
          "d904cdeb79aa583adcc31ea698a4c05283daba9089be5491f67c1a4ee48dc74b"
          "bbe6643aef846679b4cb395a352d5ed115912df696ffe0702932946d71492b44"
        },{
          "OAEP Example 1.3",
          "d94ae0832e6445ce42331cb06d531a82b1db4baad30f746dc916df24d4e3c245"
          "1fff59a6423eb0e1d02d4fe646cf699dfd818c6e97b051",
          "2514df4695755a67b288eaf4905c36eec66fd2fd",
          "423736ed035f6026af276c35c0b3741b365e5f76ca091b4e8c29e2f0befee603"
          "595aa8322d602d2e625e95eb81b2f1c9724e822eca76db8618cf09c5343503a4"
          "360835b5903bc637e3879fb05e0ef32685d5aec5067cd7cc96fe4b2670b6eac3"
          "066b1fcf5686b68589aafb7d629b02d8f8625ca3833624d4800fb081b1cf94eb"
        },{
          "OAEP Example 1.4",
          "52e650d98e7f2a048b4f86852153b97e01dd316f346a19f67a85",
          "c4435a3e1a18a68b6820436290a37cefb85db3fb",
          "45ead4ca551e662c9800f1aca8283b0525e6abae30be4b4aba762fa40fd3d38e"
          "22abefc69794f6ebbbc05ddbb11216247d2f412fd0fba87c6e3acd888813646f"
          "d0e48e785204f9c3f73d6d8239562722dddd8771fec48b83a31ee6f592c4cfd4"
          "bc88174f3b13a112aae3b9f7b80e0fc6f7255ba880dc7d8021e22ad6a85f0755"
        },{
          "OAEP Example 1.5",
          "8da89fd9e5f974a29feffb462b49180f6cf9e802",
          "b318c42df3be0f83fea823f5a7b47ed5e425a3b5",
          "36f6e34d94a8d34daacba33a2139d00ad85a9345a86051e73071620056b920e2"
          "19005855a213a0f23897cdcd731b45257c777fe908202befdd0b58386b1244ea"
          "0cf539a05d5d10329da44e13030fd760dcd644cfef2094d1910d3f433e1c7c6d"
          "d18bc1f2df7f643d662fb9dd37ead9059190f4fa66ca39e869c4eb449cbdc439"
        },{
          "OAEP Example 1.6",
          "26521050844271",
          "e4ec0982c2336f3a677f6a356174eb0ce887abc2",
          "42cee2617b1ecea4db3f4829386fbd61dafbf038e180d837c96366df24c097b4"
          "ab0fac6bdf590d821c9f10642e681ad05b8d78b378c0f46ce2fad63f74e0ad3d"
          "f06b075d7eb5f5636f8d403b9059ca761b5c62bb52aa45002ea70baace08ded2"
          "43b9d8cbd62a68ade265832b56564e43a6fa42ed199a099769742df1539e8255"
        }
      }
    },
    {
      "Example 2: A 1025-bit RSA key pair",
      "01947c7fce90425f47279e70851f25d5e62316fe8a1df19371e3e628e260543e"
      "4901ef6081f68c0b8141190d2ae8daba7d1250ec6db636e944ec3722877c7c1d"
      "0a67f14b1694c5f0379451a43e49a32dde83670b73da91a1c99bc23b436a6005"
      "5c610f0baf99c1a079565b95a3f1526632d1d4da60f20eda25e653c4f002766f"
      "45",
      "010001",
      "0823f20fadb5da89088a9d00893e21fa4a1b11fbc93c64a3be0baaea97fb3b93"
      "c3ff713704c19c963c1d107aae99054739f79e02e186de86f87a6ddefea6d8cc"
      "d1d3c81a47bfa7255be20601a4a4b2f08a167b5e279d715b1b455bdd7eab2459"
      "41d9768b9acefb3ccda5952da3cee72525b4501663a8ee15c9e992d92462fe39",
      {
        {
          "OAEP Example 2.1",
          "8ff00caa605c702830634d9a6c3d42c652b58cf1d92fec570beee7",
          "8c407b5ec2899e5099c53e8ce793bf94e71b1782",
          "0181af8922b9fcb4d79d92ebe19815992fc0c1439d8bcd491398a0f4ad3a329a"
          "5bd9385560db532683c8b7da04e4b12aed6aacdf471c34c9cda891addcc2df34"
          "56653aa6382e9ae59b54455257eb099d562bbe10453f2b6d13c59c02e10f1f8a"
          "bb5da0d0570932dacf2d0901db729d0fefcc054e70968ea540c81b04bcaefe72"
          "0e"
        },{
          "OAEP Example 2.2",
          "2d",
          "b600cf3c2e506d7f16778c910d3a8b003eee61d5",
          "018759ff1df63b2792410562314416a8aeaf2ac634b46f940ab82d64dbf165ee"
          "e33011da749d4bab6e2fcd18129c9e49277d8453112b429a222a8471b0709939"
          "98e758861c4d3f6d749d91c4290d332c7a4ab3f7ea35ff3a07d497c955ff0ffc"
          "95006b62c6d296810d9bfab024196c7934012c2df978ef299aba239940cba102"
          "45"
        },{
          "OAEP Example 2.3",
          "74fc88c51bc90f77af9d5e9a4a70133d4b4e0b34da3c37c7ef8e",
          "a73768aeeaa91f9d8c1ed6f9d2b63467f07ccae3",
          "018802bab04c60325e81c4962311f2be7c2adce93041a00719c88f957575f2c7"
          "9f1b7bc8ced115c706b311c08a2d986ca3b6a9336b147c29c6f229409ddec651"
          "bd1fdd5a0b7f610c9937fdb4a3a762364b8b3206b4ea485fd098d08f63d4aa8b"
          "b2697d027b750c32d7f74eaf5180d2e9b66b17cb2fa55523bc280da10d14be20"
          "53"
        },{
          "OAEP Example 2.4",
          "a7eb2a5036931d27d4e891326d99692ffadda9bf7efd3e34e622c4adc085f721"
          "dfe885072c78a203b151739be540fa8c153a10f00a",
          "9a7b3b0e708bd96f8190ecab4fb9b2b3805a8156",
          "00a4578cbc176318a638fba7d01df15746af44d4f6cd96d7e7c495cbf425b09c"
          "649d32bf886da48fbaf989a2117187cafb1fb580317690e3ccd446920b7af82b"
          "31db5804d87d01514acbfa9156e782f867f6bed9449e0e9a2c09bcecc6aa0876"
          "36965e34b3ec766f2fe2e43018a2fddeb140616a0e9d82e5331024ee0652fc76"
          "41"
        },{
          "OAEP Example 2.5",
          "2ef2b066f854c33f3bdcbb5994a435e73d6c6c",
          "eb3cebbc4adc16bb48e88c8aec0e34af7f427fd3",
          "00ebc5f5fda77cfdad3c83641a9025e77d72d8a6fb33a810f5950f8d74c73e8d"
          "931e8634d86ab1246256ae07b6005b71b7f2fb98351218331ce69b8ffbdc9da0"
          "8bbc9c704f876deb9df9fc2ec065cad87f9090b07acc17aa7f997b27aca48806"
          "e897f771d95141fe4526d8a5301b678627efab707fd40fbebd6e792a25613e7a"
          "ec",
        },{
          "OAEP Example 2.6",
          "8a7fb344c8b6cb2cf2ef1f643f9a3218f6e19bba89c0",
          "4c45cf4d57c98e3d6d2095adc51c489eb50dff84",
          "010839ec20c27b9052e55befb9b77e6fc26e9075d7a54378c646abdf51e445bd"
          "5715de81789f56f1803d9170764a9e93cb78798694023ee7393ce04bc5d8f8c5"
          "a52c171d43837e3aca62f609eb0aa5ffb0960ef04198dd754f57f7fbe6abf765"
          "cf118b4ca443b23b5aab266f952326ac4581100644325f8b721acd5d04ff14ef"
          "3a"
        }
      }
    },
    {
      "Example 3: A 1026-bit RSA key pair",
      "02b58fec039a860700a4d7b6462f93e6cdd491161ddd74f4e810b40e3c165200"
      "6a5c277b2774c11305a4cbab5a78efa57e17a86df7a3fa36fc4b1d2249f22ec7"
      "c2dd6a463232accea906d66ebe80b5704b10729da6f833234abb5efdd4a292cb"
      "fad33b4d33fa7a14b8c397b56e3acd21203428b77cdfa33a6da706b3d8b0fc43"
      "e9",
      "010001",
      "15b48a5b5683a94670e23b5718f814fa0e13f85038f50711182cba61510581f3"
      "d22c7e232ef937e22e551d68b86e2f8cb1aad8be2e488f5df7efd279e3f568d4"
      "eaf36f80cf7141ace60fcc9113fb6c4a841fd50bbc7c512ffcbeff21487aa811"
      "eb3ca8c62005346a86de86bfa1d8a948fd3f348c22eaadf333c3ce6ce13208fd",
      {
        {
          "OAEP Example 3.1",
          "087820b569e8fa8d",
          "8ced6b196290805790e909074015e6a20b0c4894",
          "026a0485d96aebd96b4382085099b962e6a2bdec3d90c8db625e14372de85e2d"
          "5b7baab65c8faf91bb5504fb495afce5c988b3f6a52e20e1d6cbd3566c5cd1f2"
          "b8318bb542cc0ea25c4aab9932afa20760eaddec784396a07ea0ef24d4e6f4d3"
          "7e5052a7a31e146aa480a111bbe926401307e00f410033842b6d82fe5ce4dfae"
          "80"
        },{
          "OAEP Example 3.2",
          "4653acaf171960b01f52a7be63a3ab21dc368ec43b50d82ec3781e04",
          "b4291d6567550848cc156967c809baab6ca507f0",
          "024db89c7802989be0783847863084941bf209d761987e38f97cb5f6f1bc88da"
          "72a50b73ebaf11c879c4f95df37b850b8f65d7622e25b1b889e80fe80baca206"
          "9d6e0e1d829953fc459069de98ea9798b451e557e99abf8fe3d9ccf9096ebbf3"
          "e5255d3b4e1c6d2ecadf067a359eea86405acd47d5e165517ccafd47d6dbee4b"
          "f5"
        },{
          "OAEP Example 3.3",
          "d94cd0e08fa404ed89",
          "ce8928f6059558254008badd9794fadcd2fd1f65",
          "0239bce681032441528877d6d1c8bb28aa3bc97f1df584563618995797683844"
          "ca86664732f4bed7a0aab083aaabfb7238f582e30958c2024e44e57043b97950"
          "fd543da977c90cdde5337d618442f99e60d7783ab59ce6dd9d69c47ad1e962be"
          "c22d05895cff8d3f64ed5261d92b2678510393484990ba3f7f06818ae6ffce8a"
          "3a"
        },{
          "OAEP Example 3.4",
          "6cc641b6b61e6f963974dad23a9013284ef1",
          "6e2979f52d6814a57d83b090054888f119a5b9a3",
          "02994c62afd76f498ba1fd2cf642857fca81f4373cb08f1cbaee6f025c3b512b"
          "42c3e8779113476648039dbe0493f9246292fac28950600e7c0f32edf9c81b9d"
          "ec45c3bde0cc8d8847590169907b7dc5991ceb29bb0714d613d96df0f12ec5d8"
          "d3507c8ee7ae78dd83f216fa61de100363aca48a7e914ae9f42ddfbe943b09d9"
          "a0"
        },{
          "OAEP Example 3.5",
          "df5151832b61f4f25891fb4172f328d2eddf8371ffcfdbe997939295f30eca69"
          "18017cfda1153bf7a6af87593223",
          "2d760bfe38c59de34cdc8b8c78a38e66284a2d27",
          "0162042ff6969592a6167031811a239834ce638abf54fec8b99478122afe2ee6"
          "7f8c5b18b0339805bfdbc5a4e6720b37c59cfba942464c597ff532a119821545"
          "fd2e59b114e61daf71820529f5029cf524954327c34ec5e6f5ba7efcc4de943a"
          "b8ad4ed787b1454329f70db798a3a8f4d92f8274e2b2948ade627ce8ee33e43c"
          "60",
        },{
          "OAEP Example 3.6",
          "3c3bad893c544a6d520ab022319188c8d504b7a788b850903b85972eaa18552e"
          "1134a7ad6098826254ff7ab672b3d8eb3158fac6d4cbaef1",
          "f174779c5fd3cfe007badcb7a36c9b55bfcfbf0e",
          "00112051e75d064943bc4478075e43482fd59cee0679de6893eec3a943daa490"
          "b9691c93dfc0464b6623b9f3dbd3e70083264f034b374f74164e1a00763725e5"
          "74744ba0b9db83434f31df96f6e2a26f6d8eba348bd4686c2238ac07c37aac37"
          "85d1c7eea2f819fd91491798ed8e9cef5e43b781b0e0276e37c43ff9492d0057"
          "30"
        }
      }
    },
    {
      "Example 4: A 1027-bit RSA key pair",
      "051240b6cc0004fa48d0134671c078c7c8dec3b3e2f25bc2564467339db38853"
      "d06b85eea5b2de353bff42ac2e46bc97fae6ac9618da9537a5c8f553c1e35762"
      "5991d6108dcd7885fb3a25413f53efcad948cb35cd9b9ae9c1c67626d113d57d"
      "de4c5bea76bb5bb7de96c00d07372e9685a6d75cf9d239fa148d70931b5f3fb0"
      "39",
      "010001",
      "0411ffca3b7ca5e9e9be7fe38a85105e353896db05c5796aecd2a725161eb365"
      "1c8629a9b862b904d7b0c7b37f8cb5a1c2b54001018a00a1eb2cafe4ee4e9492"
      "c348bc2bedab4b9ebbf064e8eff322b9009f8eec653905f40df88a3cdc49d456"
      "7f75627d41aca624129b46a0b7c698e5e65f2b7ba102c749a10135b6540d0401",
      {
        {
          "OAEP Example 4.1",
          "4a86609534ee434a6cbca3f7e962e76d455e3264c19f605f6e5ff6137c65c56d"
          "7fb344cd52bc93374f3d166c9f0c6f9c506bad19330972d2",
          "1cac19ce993def55f98203f6852896c95ccca1f3",
          "04cce19614845e094152a3fe18e54e3330c44e5efbc64ae16886cb1869014cc5"
          "781b1f8f9e045384d0112a135ca0d12e9c88a8e4063416deaae3844f60d6e96f"
          "e155145f4525b9a34431ca3766180f70e15a5e5d8e8b1a516ff870609f13f896"
          "935ced188279a58ed13d07114277d75c6568607e0ab092fd803a223e4a8ee0b1"
          "a8"
        },{
          "OAEP Example 4.2",
          "b0adc4f3fe11da59ce992773d9059943c03046497ee9d9f9a06df1166db46d98"
          "f58d27ec074c02eee6cbe2449c8b9fc5080c5c3f4433092512ec46aa793743c8",
          "f545d5897585e3db71aa0cb8da76c51d032ae963",
          "0097b698c6165645b303486fbf5a2a4479c0ee85889b541a6f0b858d6b6597b1"
          "3b854eb4f839af03399a80d79bda6578c841f90d645715b280d37143992dd186"
          "c80b949b775cae97370e4ec97443136c6da484e970ffdb1323a20847821d3b18"
          "381de13bb49aaea66530c4a4b8271f3eae172cd366e07e6636f1019d2a28aed1"
          "5e"
        },{
          "OAEP Example 4.3",
          "bf6d42e701707b1d0206b0c8b45a1c72641ff12889219a82bdea965b5e79a96b"
          "0d0163ed9d578ec9ada20f2fbcf1ea3c4089d83419ba81b0c60f3606da99",
          "ad997feef730d6ea7be60d0dc52e72eacbfdd275",
          "0301f935e9c47abcb48acbbe09895d9f5971af14839da4ff95417ee453d1fd77"
          "319072bb7297e1b55d7561cd9d1bb24c1a9a37c619864308242804879d86ebd0"
          "01dce5183975e1506989b70e5a83434154d5cbfd6a24787e60eb0c658d2ac193"
          "302d1192c6e622d4a12ad4b53923bca246df31c6395e37702c6a78ae081fb9d0"
          "65"
        },{
          "OAEP Example 4.4",
          "fb2ef112f5e766eb94019297934794f7be2f6fc1c58e",
          "136454df5730f73c807a7e40d8c1a312ac5b9dd3",
          "02d110ad30afb727beb691dd0cf17d0af1a1e7fa0cc040ec1a4ba26a42c59d0a"
          "796a2e22c8f357ccc98b6519aceb682e945e62cb734614a529407cd452bee3e4"
          "4fece8423cc19e55548b8b994b849c7ecde4933e76037e1d0ce44275b08710c6"
          "8e430130b929730ed77e09b015642c5593f04e4ffb9410798102a8e96ffdfe11"
          "e4"
        },{
          "OAEP Example 4.5",
          "28ccd447bb9e85166dabb9e5b7d1adadc4b9d39f204e96d5e440ce9ad928bc1c"
          "2284",
          "bca8057f824b2ea257f2861407eef63d33208681",
          "00dbb8a7439d90efd919a377c54fae8fe11ec58c3b858362e23ad1b8a4431079"
          "9066b99347aa525691d2adc58d9b06e34f288c170390c5f0e11c0aa3645959f1"
          "8ee79e8f2be8d7ac5c23d061f18dd74b8c5f2a58fcb5eb0c54f99f01a8324756"
          "8292536583340948d7a8c97c4acd1e98d1e29dc320e97a260532a8aa7a758a1e"
          "c2"
        },{
          "OAEP Example 4.6",
          "f22242751ec6b1",
          "2e7e1e17f647b5ddd033e15472f90f6812f3ac4e",
          "00a5ffa4768c8bbecaee2db77e8f2eec99595933545520835e5ba7db9493d3e1"
          "7cddefe6a5f567624471908db4e2d83a0fbee60608fc84049503b2234a07dc83"
          "b27b22847ad8920ff42f674ef79b76280b00233d2b51b8cb2703a9d42bfbc825"
          "0c96ec32c051e57f1b4ba528db89c37e4c54e27e6e64ac69635ae887d9541619"
          "a9"
        }
      }
    },
    {
      "Example 5: A 1028-bit RSA key pair",
      "0aadf3f9c125e5d891f31ac448e993defe580f802b45f9d7f22ba5021e9c4757"
      "6b5a1e68031ba9db4e6dabe4d96a1d6f3d267268cff408005f118efcadb99888"
      "d1c234467166b2a2b849a05a889c060ac0da0c5fae8b55f309ba62e703742fa0"
      "326f2d10b011021489ff497770190d895fd39f52293c39efd73a698bdab9f10e"
      "d9",
      "010001",
      "0256eb4cba7067f2d2be540dcdff4582a36b7d31d1c9099bb214b79848466a26"
      "8f80f58a49ac04c0e3648934a0206c04537c19b236643a6082732144df75fa21"
      "7588f794682be89168276dc726c5c0cbdb84d31bbf26d0a43af495717f7d528a"
      "cfee341561f6ff3cae05c578f8470d9682f9c0d072f9f6068b56d5880f682be2"
      "c5",
      {
        {
          "OAEP Example 5.1",
          "af71a901e3a61d3132f0fc1fdb474f9ea6579257ffc24d164170145b3dbde8",
          "44c92e283f77b9499c603d963660c87d2f939461",
          "036046a4a47d9ed3ba9a89139c105038eb7492b05a5d68bfd53accff4597f7a6"
          "8651b47b4a4627d927e485eed7b4566420e8b409879e5d606eae251d22a5df79"
            "9f7920bfc117b992572a53b1263146bcea03385cc5e853c9a101c8c3e1bda31a"
          "519807496c6cb5e5efb408823a352b8fa0661fb664efadd593deb99fff5ed000"
          "e5"
        },{
          "OAEP Example 5.2",
          "a3b844a08239a8ac41605af17a6cfda4d350136585903a417a79268760519a4b"
          "4ac3303ec73f0f87cfb32399",
          "cb28f5860659fceee49c3eeafce625a70803bd32",
          "03d6eb654edce615bc59f455265ed4e5a18223cbb9be4e4069b473804d5de96f"
          "54dcaaa603d049c5d94aa1470dfcd2254066b7c7b61ff1f6f6770e3215c51399"
          "fd4e34ec5082bc48f089840ad04354ae66dc0f1bd18e461a33cc1258b443a283"
          "7a6df26759aa2302334986f87380c9cc9d53be9f99605d2c9a97da7b0915a4a7"
          "ad"
        },{
          "OAEP Example 5.3",
          "308b0ecbd2c76cb77fc6f70c5edd233fd2f20929d629f026953bb62a8f4a3a31"
          "4bde195de85b5f816da2aab074d26cb6acddf323ae3b9c678ac3cf12fbdde7",
          "2285f40d770482f9a9efa2c72cb3ac55716dc0ca",
          "0770952181649f9f9f07ff626ff3a22c35c462443d905d456a9fd0bff43cac2c"
          "a7a9f554e9478b9acc3ac838b02040ffd3e1847de2e4253929f9dd9ee4044325"
          "a9b05cabb808b2ee840d34e15d105a3f1f7b27695a1a07a2d73fe08ecaaa3c9c"
          "9d4d5a89ff890d54727d7ae40c0ec1a8dd86165d8ee2c6368141016a48b55b69"
          "67"
        },{
          "OAEP Example 5.4",
          "15c5b9ee1185",
          "49fa45d3a78dd10dfd577399d1eb00af7eed5513",
          "0812b76768ebcb642d040258e5f4441a018521bd96687e6c5e899fcd6c17588f"
          "f59a82cc8ae03a4b45b31299af1788c329f7dcd285f8cf4ced82606b97612671"
          "a45bedca133442144d1617d114f802857f0f9d739751c57a3f9ee400912c61e2"
          "e6992be031a43dd48fa6ba14eef7c422b5edc4e7afa04fdd38f402d1c8bb719a"
          "bf"
        },{
          "OAEP Example 5.5",
          "21026e6800c7fa728fcaaba0d196ae28d7a2ac4ffd8abce794f0985f60c8a673"
          "7277365d3fea11db8923a2029a",
          "f0287413234cc5034724a094c4586b87aff133fc",
          "07b60e14ec954bfd29e60d0047e789f51d57186c63589903306793ced3f68241"
          "c743529aba6a6374f92e19e0163efa33697e196f7661dfaaa47aac6bde5e51de"
          "b507c72c589a2ca1693d96b1460381249b2cdb9eac44769f2489c5d3d2f99f0e"
          "e3c7ee5bf64a5ac79c42bd433f149be8cb59548361640595513c97af7bc25097"
          "23"
        },{
          "OAEP Example 5.6",
          "541e37b68b6c8872b84c02",
          "d9fba45c96f21e6e26d29eb2cdcb6585be9cb341",
          "08c36d4dda33423b2ed6830d85f6411ba1dcf470a1fae0ebefee7c089f256cef"
          "74cb96ea69c38f60f39abee44129bcb4c92de7f797623b20074e3d9c2899701e"
          "d9071e1efa0bdd84d4c3e5130302d8f0240baba4b84a71cc032f2235a5ff0fae"
          "277c3e8f9112bef44c9ae20d175fc9a4058bfc930ba31b02e2e4f444483710f2"
          "4a"
        }
      }
    },
    {
      "Example 6: A 1029-bit RSA key pair",
      "12b17f6dad2ecd19ff46dc13f7860f09e0e0cfb677b38a52592305ceaf022c16"
      "6db90d04ac29e33f7dd12d9faf66e0816bb63ead267cc7d46c17c37be214bca2"
      "a22d723a64e44407436b6fc965729aefc2554f376cd5dcea68293780a62bf39d"
      "0029485a160bbb9e5dc0972d21a504f52e5ee028aa416332f510b2e9cff5f722"
      "af",
      "010001",
      "0295eca3560618369559cecd303aa9cfdafc1d9f06959df75ffef929aa896961"
      "bcd190dc6997eda7f5963e724d07b4dc11f3065e5ae97d96835112280b9084bb"
      "14f2a21ebd4e889d41b9c4132ec1956fcab8bb2fed0575884936522c5ff7d332"
      "61904824e7cadee4e0bb372d2457cf78e2bd1286228ff83f10731ce63c90cff3"
      "f9",
      {
        {
          "OAEP Example 6.1",
          "4046ca8baa3347ca27f49e0d81f9cc1d71be9ba517d4",
          "dd0f6cfe415e88e5a469a51fbba6dfd40adb4384",
          "0630eebcd2856c24f798806e41f9e67345eda9ceda386acc9facaea1eeed06ac"
          "e583709718d9d169fadf414d5c76f92996833ef305b75b1e4b95f662a20faedc"
          "3bae0c4827a8bf8a88edbd57ec203a27a841f02e43a615bab1a8cac0701de34d"
          "ebdef62a088089b55ec36ea7522fd3ec8d06b6a073e6df833153bc0aefd93bd1"
          "a3"
        },{
          "OAEP Example 6.2",
          "5cc72c60231df03b3d40f9b57931bc31109f972527f28b19e7480c7288cb3c92"
          "b22512214e4be6c914792ddabdf57faa8aa7",
          "8d14bd946a1351148f5cae2ed9a0c653e85ebd85",
          "0ebc37376173a4fd2f89cc55c2ca62b26b11d51c3c7ce49e8845f74e7607317c"
          "436bc8d23b9667dfeb9d087234b47bc6837175ae5c0559f6b81d7d22416d3e50"
          "f4ac533d8f0812f2db9e791fe9c775ac8b6ad0f535ad9ceb23a4a02014c58ab3"
          "f8d3161499a260f39348e714ae2a1d3443208fd8b722ccfdfb393e98011f99e6"
          "3f"
        },{
          "OAEP Example 6.3",
          "b20e651303092f4bccb43070c0f86d23049362ed96642fc5632c27db4a52e3d8"
          "31f2ab068b23b149879c002f6bf3feee97591112562c",
          "6c075bc45520f165c0bf5ea4c5df191bc9ef0e44",
          "0a98bf1093619394436cf68d8f38e2f158fde8ea54f3435f239b8d06b8321844"
          "202476aeed96009492480ce3a8d705498c4c8c68f01501dc81db608f60087350"
          "c8c3b0bd2e9ef6a81458b7c801b89f2e4fe99d4900ba6a4b5e5a96d865dc676c"
          "7755928794130d6280a8160a190f2df3ea7cf9aa0271d88e9e6905ecf1c5152d"
          "65"
        },{
          "OAEP Example 6.4",
          "684e3038c5c041f7",
          "3bbc3bd6637dfe12846901029bf5b0c07103439c",
          "008e7a67cacfb5c4e24bec7dee149117f19598ce8c45808fef88c608ff9cd6e6"
          "95263b9a3c0ad4b8ba4c95238e96a8422b8535629c8d5382374479ad13fa3997"
          "4b242f9a759eeaf9c83ad5a8ca18940a0162ba755876df263f4bd50c6525c560"
          "90267c1f0e09ce0899a0cf359e88120abd9bf893445b3cae77d3607359ae9a52"
          "f8"
        },{
          "OAEP Example 6.5",
          "32488cb262d041d6e4dd35f987bf3ca696db1f06ac29a44693",
          "b46b41893e8bef326f6759383a83071dae7fcabc",
          "00003474416c7b68bdf961c385737944d7f1f40cb395343c693cc0b4fe63b31f"
          "edf1eaeeac9ccc0678b31dc32e0977489514c4f09085f6298a9653f01aea4045"
          "ff582ee887be26ae575b73eef7f3774921e375a3d19adda0ca31aa1849887c1f"
          "42cac9677f7a2f4e923f6e5a868b38c084ef187594dc9f7f048fea2e02955384"
          "ab"
        },{
          "OAEP Example 6.6",
          "50ba14be8462720279c306ba",
          "0a2403312a41e3d52f060fbc13a67de5cf7609a7",
          "0a026dda5fc8785f7bd9bf75327b63e85e2c0fdee5dadb65ebdcac9ae1de95c9"
          "2c672ab433aa7a8e69ce6a6d8897fac4ac4a54de841ae5e5bbce7687879d7963"
          "4cea7a30684065c714d52409b928256bbf53eabcd5231eb7259504537399bd29"
          "164b726d33a46da701360a4168a091ccab72d44a62fed246c0ffea5b1348ab54"
          "70"
        }
      }
    },
    {
      "Example 7: A 1030-bit RSA key pair",
      "311179f0bcfc9b9d3ca315d00ef30d7bdd3a2cfae9911bfedcb948b3a4782d07"
      "32b6ab44aa4bf03741a644dc01bec3e69b01a033e675d8acd7c4925c6b1aec31"
      "19051dfd89762d215d45475ffcb59f908148623f37177156f6ae86dd7a7c5f43"
      "dc1e1f908254058a284a5f06c0021793a87f1ac5feff7dcaee69c5e51a3789e3"
      "73",
      "010001",
      "070cfcff2feb8276e27432c45dfee48f49b7917d6530e1f0ca3460f32e027617"
      "4487c56e22a45d2500d7775495219d7d165a9cf3bd92c32af9a98d8dc9cc2968"
      "00adc94a0a54fb40f34291bf84ee8ea12b6f109359c6d3542a50f9c767f5cfff"
      "05a681c2e656fb77caaadb4be9468d8abcd4df98f58e86d2053fa1349f748e21"
      "b1",
      {
        {
          "OAEP Example 7.1",
          "47aae909",
          "43dd09a07ff4cac71caa4632ee5e1c1daee4cd8f",
          "1688e4ce7794bba6cb7014169ecd559cede2a30b56a52b68d9fe18cf1973ef97"
          "b2a03153951c755f6294aa49adbdb55845ab6875fb3986c93ecf927962840d28"
          "2f9e54ce8b690f7c0cb8bbd73440d9571d1b16cd9260f9eab4783cc482e5223d"
          "c60973871783ec27b0ae0fd47732cbc286a173fc92b00fb4ba6824647cd93c85"
          "c1"
        },{
          "OAEP Example 7.2",
          "1d9b2e2223d9bc13bfb9f162ce735db48ba7c68f6822a0a1a7b6ae165834e7",
          "3a9c3cec7b84f9bd3adecbc673ec99d54b22bc9b",
          "1052ed397b2e01e1d0ee1c50bf24363f95e504f4a03434a08fd822574ed6b973"
          "6edbb5f390db10321479a8a139350e2bd4977c3778ef331f3e78ae118b268451"
          "f20a2f01d471f5d53c566937171b2dbc2d4bde459a5799f0372d6574239b2323"
          "d245d0bb81c286b63c89a361017337e4902f88a467f4c7f244bfd5ab46437ff3"
          "b6"
        },{
          "OAEP Example 7.3",
          "d976fc",
          "76a75e5b6157a556cf8884bb2e45c293dd545cf5",
          "2155cd843ff24a4ee8badb7694260028a490813ba8b369a4cbf106ec148e5298"
          "707f5965be7d101c1049ea8584c24cd63455ad9c104d686282d3fb803a4c11c1"
          "c2e9b91c7178801d1b6640f003f5728df007b8a4ccc92bce05e41a27278d7c85"
          "018c52414313a5077789001d4f01910b72aad05d220aa14a58733a7489bc5455"
          "6b"
        },{
          "OAEP Example 7.4",
          "d4738623df223aa43843df8467534c41d013e0c803c624e263666b239bde40a5"
          "f29aeb8de79e3daa61dd0370f49bd4b013834b98212aef6b1c5ee373b3cb",
          "7866314a6ad6f2b250a35941db28f5864b585859",
          "0ab14c373aeb7d4328d0aaad8c094d88b9eb098b95f21054a29082522be7c27a"
          "312878b637917e3d819e6c3c568db5d843802b06d51d9e98a2be0bf40c031423"
          "b00edfbff8320efb9171bd2044653a4cb9c5122f6c65e83cda2ec3c126027a9c"
          "1a56ba874d0fea23f380b82cf240b8cf540004758c4c77d934157a74f3fc12bf"
          "ac"
        },{
          "OAEP Example 7.5",
          "bb47231ca5ea1d3ad46c99345d9a8a61",
          "b2166ed472d58db10cab2c6b000cccf10a7dc509",
          "028387a318277434798b4d97f460068df5298faba5041ba11761a1cb7316b241"
          "84114ec500257e2589ed3b607a1ebbe97a6cc2e02bf1b681f42312a33b7a77d8"
          "e7855c4a6de03e3c04643f786b91a264a0d6805e2cea91e68177eb7a64d9255e"
          "4f27e713b7ccec00dc200ebd21c2ea2bb890feae4942df941dc3f97890ed3474"
          "78"
        },{
          "OAEP Example 7.6",
          "2184827095d35c3f86f600e8e59754013296",
          "52673bde2ca166c2aa46131ac1dc808d67d7d3b1",
          "14c678a94ad60525ef39e959b2f3ba5c097a94ff912b67dbace80535c187abd4"
          "7d075420b1872152bba08f7fc31f313bbf9273c912fc4c0149a9b0cfb79807e3"
          "46eb332069611bec0ff9bcd168f1f7c33e77313cea454b94e2549eecf002e2ac"
          "f7f6f2d2845d4fe0aab2e5a92ddf68c480ae11247935d1f62574842216ae6741"
          "15"
        }
      }
    },
    {
      "Example 8: A 1031-bit RSA key pair",
      "5bdf0e30d321dda5147f882408fa69195480df8f80d3f6e8bf5818504f36427c"
      "a9b1f5540b9c65a8f6974cf8447a244d9280201bb49fcbbe6378d1944cd227e2"
      "30f96e3d10f819dcef276c64a00b2a4b6701e7d01de5fabde3b1e9a0df82f463"
      "1359cd22669647fbb1717246134ed7b497cfffbdc42b59c73a96ed90166212df"
      "f7",
      "010001",
      "0f7d1e9e5aaa25fd13e4a0663ae144e0d15f5cd18bcdb09df2cc7e64e3c5e915"
      "ad62645304161d098c715bb7ab8bd01d07eaf3fed7c7ed08af2a8a62ef44ab16"
      "b320e14af72a48f96afe262a0ae4cf65e635e910790cd4ee5cea768a4b2639f7"
      "e6f677b3f0bb6be32b75747d8909036f0264f58d401cdba131716157a75ecf63"
      "31",
      {
        {
          "OAEP Example 8.1",
          "050b755e5e6880f7b9e9d692a74c37aae449b31bfea6deff83747a897f6c2c82"
          "5bb1adbf850a3c96994b5de5b33cbc7d4a17913a7967",
          "7706ffca1ecfb1ebee2a55e5c6e24cd2797a4125",
          "09b3683d8a2eb0fb295b62ed1fb9290b714457b7825319f4647872af889b3040"
          "9472020ad12912bf19b11d4819f49614824ffd84d09c0a17e7d17309d1291979"
          "0410aa2995699f6a86dbe3242b5acc23af45691080d6b1ae810fb3e3057087f0"
          "970092ce00be9562ff4053b6262ce0caa93e13723d2e3a5ba075d45f0d61b54b"
          "61"
        },{
          "OAEP Example 8.2",
          "4eb68dcd93ca9b19df111bd43608f557026fe4aa1d5cfac227a3eb5ab9548c18"
          "a06dded23f81825986b2fcd71109ecef7eff88873f075c2aa0c469f69c92bc",
          "a3717da143b4dcffbc742665a8fa950585548343",
          "2ecf15c97c5a15b1476ae986b371b57a24284f4a162a8d0c8182e7905e792256"
          "f1812ba5f83f1f7a130e42dcc02232844edc14a31a68ee97ae564a383a341165"
          "6424c5f62ddb646093c367be1fcda426cf00a06d8acb7e57776fbbd855ac3df5"
          "06fc16b1d7c3f2110f3d8068e91e186363831c8409680d8da9ecd8cf1fa20ee3"
          "9d"
        },{
          "OAEP Example 8.3",
          "8604ac56328c1ab5ad917861",
          "ee06209073cca026bb264e5185bf8c68b7739f86",
          "4bc89130a5b2dabb7c2fcf90eb5d0eaf9e681b7146a38f3173a3d9cfec52ea9e"
          "0a41932e648a9d69344c50da763f51a03c95762131e8052254dcd2248cba40fd"
          "31667786ce05a2b7b531ac9dac9ed584a59b677c1a8aed8c5d15d68c05569e2b"
          "e780bf7db638fd2bfd2a85ab276860f3777338fca989ffd743d13ee08e0ca989"
          "3f"
        },{
          "OAEP Example 8.4",
          "fdda5fbf6ec361a9d9a4ac68af216a0686f438b1e0e5c36b955f74e107f39c0d"
          "ddcc",
          "990ad573dc48a973235b6d82543618f2e955105d",
          "2e456847d8fc36ff0147d6993594b9397227d577752c79d0f904fcb039d4d812"
          "fea605a7b574dd82ca786f93752348438ee9f5b5454985d5f0e1699e3e7ad175"
          "a32e15f03deb042ab9fe1dd9db1bb86f8c089ccb45e7ef0c5ee7ca9b7290ca6b"
          "15bed47039788a8a93ff83e0e8d6244c71006362deef69b6f416fb3c684383fb"
          "d0"
        },{
          "OAEP Example 8.5",
          "4a5f4914bee25de3c69341de07",
          "ecc63b28f0756f22f52ac8e6ec1251a6ec304718",
          "1fb9356fd5c4b1796db2ebf7d0d393cc810adf6145defc2fce714f79d93800d5"
          "e2ac211ea8bbecca4b654b94c3b18b30dd576ce34dc95436ef57a09415645923"
          "359a5d7b4171ef22c24670f1b229d3603e91f76671b7df97e7317c97734476d5"
          "f3d17d21cf82b5ba9f83df2e588d36984fd1b584468bd23b2e875f32f68953f7"
          "b2"
        },{
          "OAEP Example 8.6",
          "8e07d66f7b880a72563abcd3f35092bc33409fb7f88f2472be",
          "3925c71b362d40a0a6de42145579ba1e7dd459fc",
          "3afd9c6600147b21798d818c655a0f4c9212db26d0b0dfdc2a7594ccb3d22f5b"
          "f1d7c3e112cd73fc7d509c7a8bafdd3c274d1399009f9609ec4be6477e453f07"
          "5aa33db382870c1c3409aef392d7386ae3a696b99a94b4da0589447e955d16c9"
          "8b17602a59bd736279fcd8fb280c4462d590bfa9bf13fed570eafde97330a2c2"
          "10"
        }
      }
    },
    {
      "Example 9: A 1536-bit RSA key pair",
      "cf2cd41e34ca3a728ea5cb8aff64c36d27bdef5364e336fd68d3123c5a196a8c"
      "287013e853d5156d58d151954520fb4f6d7b17abb6817765909c576119659d90"
      "2b1906ed8a2b10c155c24d124528dab9eeae379beac66e4a411786dcb8fd0062"
      "ebc030de1219a04c2a8c1b7dd3131e4d6b6caee2e31a5ed41ac1509b2ef1ee2a"
      "b18364be568ca941c25ecc84ff9d643b5ec1aaae102a20d73f479b780fd6da91"
      "075212d9eac03a0674d899eba2e431f4c44b615b6ba2232bd4b33baed73d625d",
      "010001",
      "198c141e23715a92bccf6a119a5bc11389468d2811f548d727e17b4ab0eb986d"
      "6f211efb53b71f7ccbea87ee69c75ee615008c5332deb52bf390abdfbfe37d72"
      "05368159b2638c1de326e21d22251f0fb5848b3bf15005d2a74330f0afe916ee"
      "62ccc1344d1d83a709e60676273840f7f377424a5e0a4da75f01b31ff76819cf"
      "9cbfdd215243c3917c03ef38199312e567b3bf7aed3ab457f371ef8a1423f45b"
      "68c6e282ec111bba2833b987fd69fad83bc1b8c613c5e1ea16c11ed125ea7ec1",
      {
        {
          "OAEP Example 9.1",
          "f735fd55ba92592c3b52b8f9c4f69aaa1cbef8fe88add095595412467f9cf4ec"
          "0b896c59eda16210e7549c8abb10cdbc21a12ec9b6b5b8fd2f10399eb6",
          "8ec965f134a3ec9931e92a1ca0dc8169d5ea705c",
          "267bcd118acab1fc8ba81c85d73003cb8610fa55c1d97da8d48a7c7f06896a4d"
          "b751aa284255b9d36ad65f37653d829f1b37f97b8001942545b2fc2c55a7376c"
          "a7a1be4b1760c8e05a33e5aa2526b8d98e317088e7834c755b2a59b12631a182"
          "c05d5d43ab1779264f8456f515ce57dfdf512d5493dab7b7338dc4b7d78db9c0"
          "91ac3baf537a69fc7f549d979f0eff9a94fda4169bd4d1d19a69c99e33c3b554"
          "90d501b39b1edae118ff6793a153261584d3a5f39f6e682e3d17c8cd1261fa72"
        },{
          "OAEP Example 9.2",
          "81b906605015a63aabe42ddf11e1978912f5404c7474b26dce3ed482bf961ecc"
          "818bf420c54659",
          "ecb1b8b25fa50cdab08e56042867f4af5826d16c",
          "93ac9f0671ec29acbb444effc1a5741351d60fdb0e393fbf754acf0de49761a1"
          "4841df7772e9bc82773966a1584c4d72baea00118f83f35cca6e537cbd4d811f"
          "5583b29783d8a6d94cd31be70d6f526c10ff09c6fa7ce069795a3fcd0511fd5f"
          "cb564bcc80ea9c78f38b80012539d8a4ddf6fe81e9cddb7f50dbbbbcc7e5d860"
          "97ccf4ec49189fb8bf318be6d5a0715d516b49af191258cd32dc833ce6eb4673"
          "c03a19bbace88cc54895f636cc0c1ec89096d11ce235a265ca1764232a689ae8"
        },{
          "OAEP Example 9.3",
          "fd326429df9b890e09b54b18b8f34f1e24",
          "e89bb032c6ce622cbdb53bc9466014ea77f777c0",
          "81ebdd95054b0c822ef9ad7693f5a87adfb4b4c4ce70df2df84ed49c04da58ba"
          "5fc20a19e1a6e8b7a3900b22796dc4e869ee6b42792d15a8eceb56c09c69914e"
          "813cea8f6931e4b8ed6f421af298d595c97f4789c7caa612c7ef360984c21b93"
          "edc5401068b5af4c78a8771b984d53b8ea8adf2f6a7d4a0ba76c75e1dd9f658f"
          "20ded4a46071d46d7791b56803d8fea7f0b0f8e41ae3f09383a6f9585fe7753e"
          "aaffd2bf94563108beecc207bbb535f5fcc705f0dde9f708c62f49a9c90371d3"
        },{
          "OAEP Example 9.4",
          "f1459b5f0c92f01a0f723a2e5662484d8f8c0a20fc29dad6acd43bb5f3effdf4"
          "e1b63e07fdfe6628d0d74ca19bf2d69e4a0abf86d293925a796772f8088e",
          "606f3b99c0b9ccd771eaa29ea0e4c884f3189ccc",
          "bcc35f94cde66cb1136625d625b94432a35b22f3d2fa11a613ff0fca5bd57f87"
          "b902ccdc1cd0aebcb0715ee869d1d1fe395f6793003f5eca465059c88660d446"
          "ff5f0818552022557e38c08a67ead991262254f10682975ec56397768537f497"
          "7af6d5f6aaceb7fb25dec5937230231fd8978af49119a29f29e424ab8272b475"
          "62792d5c94f774b8829d0b0d9f1a8c9eddf37574d5fa248eefa9c5271fc5ec25"
          "79c81bdd61b410fa61fe36e424221c113addb275664c801d34ca8c6351e4a858"
        },{
          "OAEP Example 9.5",
          "53e6e8c729d6f9c319dd317e74b0db8e4ccca25f3c8305746e137ac63a63ef37"
          "39e7b595abb96e8d55e54f7bd41ab433378ffb911d",
          "fcbc421402e9ecabc6082afa40ba5f26522c840e",
          "232afbc927fa08c2f6a27b87d4a5cb09c07dc26fae73d73a90558839f4fd66d2"
          "81b87ec734bce237ba166698ed829106a7de6942cd6cdce78fed8d2e4d81428e"
          "66490d036264cef92af941d3e35055fe3981e14d29cbb9a4f67473063baec79a"
          "1179f5a17c9c1832f2838fd7d5e59bb9659d56dce8a019edef1bb3accc697cc6"
          "cc7a778f60a064c7f6f5d529c6210262e003de583e81e3167b89971fb8c0e15d"
          "44fffef89b53d8d64dd797d159b56d2b08ea5307ea12c241bd58d4ee278a1f2e"
        },{
          "OAEP Example 9.6",
          "b6b28ea2198d0c1008bc64",
          "23aade0e1e08bb9b9a78d2302a52f9c21b2e1ba2",
          "438cc7dc08a68da249e42505f8573ba60e2c2773d5b290f4cf9dff718e842081"
          "c383e67024a0f29594ea987b9d25e4b738f285970d195abb3a8c8054e3d79d6b"
          "9c9a8327ba596f1259e27126674766907d8d582ff3a8476154929adb1e6d1235"
          "b2ccb4ec8f663ba9cc670a92bebd853c8dbf69c6436d016f61add836e9473245"
          "0434207f9fd4c43dec2a12a958efa01efe2669899b5e604c255c55fb7166de55"
          "89e369597bb09168c06dd5db177e06a1740eb2d5c82faeca6d92fcee9931ba9f"
        }
      }
    },
    {
      "Example 10: A 2048-bit RSA key pair",
      "ae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8"
      "df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5"
      "404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2f"
      "a1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a0"
      "3381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600"
      "c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aef"
      "a2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88"
      "d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb",
      "010001",
      "056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e59"
      "6a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d"
      "19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbe"
      "be57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f10"
      "2cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564"
      "fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c43"
      "0ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101"
      "848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79",
      {
        {
          "OAEP Example 10.1",
          "8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee",
          "47e1ab7119fee56c95ee5eaad86f40d0aa63bd33",
          "53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19"
          "bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e6139614"
          "4e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfc"
          "c7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a87"
          "74a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1"
          "fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505"
          "adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464"
          "739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc"
        },{
          "OAEP Example 10.2",
          "e6ad181f053b58a904f2457510373e57",
          "6d17f5b4c1ffac351d195bf7b09d09f09a4079cf",
          "a2b1a430a9d657e2fa1c2bb5ed43ffb25c05a308fe9093c01031795f58744001"
          "10828ae58fb9b581ce9dddd3e549ae04a0985459bde6c626594e7b05dc4278b2"
          "a1465c1368408823c85e96dc66c3a30983c639664fc4569a37fe21e5a195b577"
          "6eed2df8d8d361af686e750229bbd663f161868a50615e0c337bec0ca35fec0b"
          "b19c36eb2e0bbcc0582fa1d93aacdb061063f59f2ce1ee43605e5d89eca183d2"
          "acdfe9f81011022ad3b43a3dd417dac94b4e11ea81b192966e966b182082e719"
          "64607b4f8002f36299844a11f2ae0faeac2eae70f8f4f98088acdcd0ac556e9f"
          "ccc511521908fad26f04c64201450305778758b0538bf8b5bb144a828e629795"
        },{
          "OAEP Example 10.3",
          "510a2cf60e866fa2340553c94ea39fbc256311e83e94454b4124",
          "385387514deccc7c740dd8cdf9daee49a1cbfd54",
          "9886c3e6764a8b9a84e84148ebd8c3b1aa8050381a78f668714c16d9cfd2a6ed"
          "c56979c535d9dee3b44b85c18be8928992371711472216d95dda98d2ee8347c9"
          "b14dffdff84aa48d25ac06f7d7e65398ac967b1ce90925f67dce049b7f812db0"
          "742997a74d44fe81dbe0e7a3feaf2e5c40af888d550ddbbe3bc20657a29543f8"
          "fc2913b9bd1a61b2ab2256ec409bbd7dc0d17717ea25c43f42ed27df8738bf4a"
          "fc6766ff7aff0859555ee283920f4c8a63c4a7340cbafddc339ecdb4b0515002"
          "f96c932b5b79167af699c0ad3fccfdf0f44e85a70262bf2e18fe34b850589975"
          "e867ff969d48eabf212271546cdc05a69ecb526e52870c836f307bd798780ede"
        },{
          "OAEP Example 10.4",
          "bcdd190da3b7d300df9a06e22caae2a75f10c91ff667b7c16bde8b53064a2649"
          "a94045c9",
          "5caca6a0f764161a9684f85d92b6e0ef37ca8b65",
          "6318e9fb5c0d05e5307e1683436e903293ac4642358aaa223d7163013aba87e2"
          "dfda8e60c6860e29a1e92686163ea0b9175f329ca3b131a1edd3a77759a8b97b"
          "ad6a4f8f4396f28cf6f39ca58112e48160d6e203daa5856f3aca5ffed577af49"
          "9408e3dfd233e3e604dbe34a9c4c9082de65527cac6331d29dc80e0508a0fa71"
          "22e7f329f6cca5cfa34d4d1da417805457e008bec549e478ff9e12a763c477d1"
          "5bbb78f5b69bd57830fc2c4ed686d79bc72a95d85f88134c6b0afe56a8ccfbc8"
          "55828bb339bd17909cf1d70de3335ae07039093e606d655365de6550b872cd6d"
          "e1d440ee031b61945f629ad8a353b0d40939e96a3c450d2a8d5eee9f678093c8"
        },{
          "OAEP Example 10.5",
          "a7dd6c7dc24b46f9dd5f1e91ada4c3b3df947e877232a9",
          "95bca9e3859894b3dd869fa7ecd5bbc6401bf3e4",
          "75290872ccfd4a4505660d651f56da6daa09ca1301d890632f6a992f3d565cee"
          "464afded40ed3b5be9356714ea5aa7655f4a1366c2f17c728f6f2c5a5d1f8e28"
          "429bc4e6f8f2cff8da8dc0e0a9808e45fd09ea2fa40cb2b6ce6ffff5c0e159d1"
          "1b68d90a85f7b84e103b09e682666480c657505c0929259468a314786d74eab1"
          "31573cf234bf57db7d9e66cc6748192e002dc0deea930585f0831fdcd9bc33d5"
          "1f79ed2ffc16bcf4d59812fcebcaa3f9069b0e445686d644c25ccf63b456ee5f"
          "a6ffe96f19cdf751fed9eaf35957754dbf4bfea5216aa1844dc507cb2d080e72"
          "2eba150308c2b5ff1193620f1766ecf4481bafb943bd292877f2136ca494aba0"
        },{
          "OAEP Example 10.6",
          "eaf1a73a1b0c4609537de69cd9228bbcfb9a8ca8c6c3efaf056fe4a7f4634ed0"
          "0b7c39ec6922d7b8ea2c04ebac",
          "9f47ddf42e97eea856a9bdbc714eb3ac22f6eb32",
          "2d207a73432a8fb4c03051b3f73b28a61764098dfa34c47a20995f8115aa6816"
          "679b557e82dbee584908c6e69782d7deb34dbd65af063d57fca76a5fd069492f"
          "d6068d9984d209350565a62e5c77f23038c12cb10c6634709b547c46f6b4a709"
          "bd85ca122d74465ef97762c29763e06dbc7a9e738c78bfca0102dc5e79d65b97"
          "3f28240caab2e161a78b57d262457ed8195d53e3c7ae9da021883c6db7c24afd"
          "d2322eac972ad3c354c5fcef1e146c3a0290fb67adf007066e00428d2cec18ce"
          "58f9328698defef4b2eb5ec76918fde1c198cbb38b7afc67626a9aefec4322bf"
          "d90d2563481c9a221f78c8272c82d1b62ab914e1c69f6af6ef30ca5260db4a46"
        }
      }
    }
  };
