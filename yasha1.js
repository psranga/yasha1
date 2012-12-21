// Yet another SHA1
// Doesn't do anything fancy ike utf8 decode/encode etc.
// Hence works with binary strings also.
Yasha1 = {
  SHA1Reset: function () {
    var ret = {
      Message_Digest: [0, 0, 0, 0, 0],
      Length_Low: 0, Length_High: 0,
      Message_Block: [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ],
      Message_Block_Index: 0,
      Message_Digest: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
      Computed: 0, Corrupted: 0
    };
    if (ret.Message_Block.length != 64) {
      return null;
    } else {
      return ret;
    }
  },

  SHA1Result: function (context) {
    if (context.Corrupted) {
      return 0;
    }

    if (!context.Computed) {
      this.SHA1PadMessage(context);
      context.Computed = 1;
    }
    return 1;
  },

  SHA1Input: function (context, s) {
    if (context.Computed || context.Corrupted) {
      context.Corrupted = 1;
      return;
    }

    for (var i = 0; (i < s.length) && !context.Corrupted; ++i) {

        context.Message_Block[context.Message_Block_Index++] =
          (s.charCodeAt(i) & 0xFF);

        context.Length_Low += 8;

        /* Force it to 32 bits */
        context.Length_Low &= 0xFFFFFFFF;

        if (context.Length_Low == 0) {
          context.Length_High++;
          /* Force it to 32 bits */
          context.Length_High &= 0xFFFFFFFF;
          if (context.Length_High == 0) {
            /* Message is too long */
            context.Corrupted = 1;
          }
        }

        if (context.Message_Block_Index == 64) {
            this.SHA1ProcessMessageBlock(context);
        }
    }
  },

  SHA1CircularShift: function (bits, word) {
    return ((((word) << (bits)) & 0xFFFFFFFF) |
    ((word) >>> (32-(bits))));
  },

  SHA1ProcessMessageBlock: function (context) {
      K =            /* Constants defined in SHA-1   */      
      [
          0x5A827999,
          0x6ED9EBA1,
          0x8F1BBCDC,
          0xCA62C1D6
      ];
      var t;
      var temp = 0;               /* Temporary word value         */
      // 80 integer elements
      var W = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
      var A = 0, B = 0, C = 0, D = 0, E = 0;      /* Word buffers                 */

      /*
       *  Initialize the first 16 words in the array W
       */
      for(var t = 0; t < 16; t++)
      {
          W[t] = (context.Message_Block[t * 4]) << 24;
          W[t] |= (context.Message_Block[t * 4 + 1]) << 16;
          W[t] |= (context.Message_Block[t * 4 + 2]) << 8;
          W[t] |= (context.Message_Block[t * 4 + 3]);
      }

      for(var t = 16; t < 80; t++)
      {
         W[t] = this.SHA1CircularShift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
      }

      A = context.Message_Digest[0];
      B = context.Message_Digest[1];
      C = context.Message_Digest[2];
      D = context.Message_Digest[3];
      E = context.Message_Digest[4];

      for(var t = 0; t < 20; t++)
      {
          temp =  this.SHA1CircularShift(5,A) +
                  ((B & C) | ((~B) & D)) + E + W[t] + K[0];
          temp &= 0xFFFFFFFF;
          E = D;
          D = C;
          C = this.SHA1CircularShift(30,B);
          B = A;
          A = temp;
      }

      for(var t = 20; t < 40; t++)
      {
          temp = this.SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
          temp &= 0xFFFFFFFF;
          E = D;
          D = C;
          C = this.SHA1CircularShift(30,B);
          B = A;
          A = temp;
      }

      for(var t = 40; t < 60; t++)
      {
          temp = this.SHA1CircularShift(5,A) +
                 ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
          temp &= 0xFFFFFFFF;
          E = D;
          D = C;
          C = this.SHA1CircularShift(30,B);
          B = A;
          A = temp;
      }

      for(var t = 60; t < 80; t++)
      {
          temp = this.SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
          temp &= 0xFFFFFFFF;
          E = D;
          D = C;
          C = this.SHA1CircularShift(30,B);
          B = A;
          A = temp;
      }

      context.Message_Digest[0] =
                          (context.Message_Digest[0] + A) & 0xFFFFFFFF;
      context.Message_Digest[1] =
                          (context.Message_Digest[1] + B) & 0xFFFFFFFF;
      context.Message_Digest[2] =
                          (context.Message_Digest[2] + C) & 0xFFFFFFFF;
      context.Message_Digest[3] =
                          (context.Message_Digest[3] + D) & 0xFFFFFFFF;
      context.Message_Digest[4] =
                          (context.Message_Digest[4] + E) & 0xFFFFFFFF;

      context.Message_Block_Index = 0;
  },

  SHA1PadMessage: function (context) {
      /*
       *  Check to see if the current message block is too small to hold
       *  the initial padding bits and length.  If so, we will pad the
       *  block, process it, and then continue padding into a second
       *  block.
       */
      if (context.Message_Block_Index > 55)
      {
          context.Message_Block[context.Message_Block_Index++] = 0x80;
          while(context.Message_Block_Index < 64)
          {
              context.Message_Block[context.Message_Block_Index++] = 0;
          }

          this.SHA1ProcessMessageBlock(context);

          while(context.Message_Block_Index < 56)
          {
              context.Message_Block[context.Message_Block_Index++] = 0;
          }
      }
      else
      {
          context.Message_Block[context.Message_Block_Index++] = 0x80;
          while(context.Message_Block_Index < 56)
          {
              context.Message_Block[context.Message_Block_Index++] = 0;
          }
      }

      /*
       *  Store the message length as the last 8 octets
       */
      context.Message_Block[56] = (context.Length_High >>> 24) & 0xFF;
      context.Message_Block[57] = (context.Length_High >>> 16) & 0xFF;
      context.Message_Block[58] = (context.Length_High >>> 8) & 0xFF;
      context.Message_Block[59] = (context.Length_High) & 0xFF;
      context.Message_Block[60] = (context.Length_Low >>> 24) & 0xFF;
      context.Message_Block[61] = (context.Length_Low >>> 16) & 0xFF;
      context.Message_Block[62] = (context.Length_Low >>> 8) & 0xFF;
      context.Message_Block[63] = (context.Length_Low) & 0xFF;

      this.SHA1ProcessMessageBlock(context);
  },

  hexdigest: function (context) {
    var ret = [];
    for (var i = 0; i < 5; ++i) {
      var n = context.Message_Digest[i];
      if (n < 0) {
        ret.push((Number(4294967296)+Number(n)).toString(16));
      } else {
        ret.push(Number(n).toString(16));
      }
    }
    return ret.join('');
  },

 SHA1: function (s) {
    var context = this.SHA1Reset();
    this.SHA1Input(context, s);
    this.SHA1Result(context);
    return this.hexdigest(context);
  }
};
