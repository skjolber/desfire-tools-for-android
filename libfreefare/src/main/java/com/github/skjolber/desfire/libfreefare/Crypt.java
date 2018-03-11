package com.github.skjolber.desfire.libfreefare;

import com.github.skjolber.desfire.ev1.model.random.DefaultRandomSource;
import com.github.skjolber.desfire.ev1.model.random.RandomSource;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Crypt {

	private static final String TAG = Crypt.class.getName();

    public static RandomSource randomSource = new DefaultRandomSource();

    static public byte[] K = new byte [16]; // 128 bit key
	static public byte[] K1 = new byte [16]; // 128 bit sub key
	static public byte[] K2 = new byte [16]; // 128 bit sub key
	static final public byte[] Z16  = new byte [16]; // 128 bit zero

	static Cipher cipher = null;

	static byte[] shl (byte[] bin)  // << 16 byte array
	{
		byte[] bout = new byte[16];
		for (short j = 0; j < 15; j++)  // java b[0] is the highorder
		{
			int sot = ((bin[j+1] & 0x80) >> 7);
			int sef = ( bin[j] << 1 ) | sot;
			bout[j] = ( byte)sef;
		}
		bout[15] = (byte)(bin[15] << 1);
		return bout;
	}
	//♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧
	static SecretKeySpec skeySpec = null;


	public static void subKeys(byte[] key) // make K1 K2 from key
	{
		/*
         +                    Algorithm Generate_Subkey                      +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                                                                   +
   +   Input    : K (128-bit key)                                      +
   +   Output   : K1 (128-bit first subkey)                            +
   +              K2 (128-bit second subkey)                           +
   +-------------------------------------------------------------------+
   +                                                                   +
   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
   +              const_Rb   is 0x00000000000000000000000000000087
            binary 10000111    +
   +   Variables: L          for output of AES-128 applied to 0^128    +
   +                                                                   +
   +   Step 1.  L := AES-128(K, const_Zero);                           +
   +   Step 2.  if MSB(L) is equal to 0                                +
   +            then    K1 := L << 1;                                  +
   +            else    K1 := (L << 1) XOR const_Rb;                   +
   +   Step 3.  if MSB(K1) is equal to 0                               +
   +            then    K2 := K1 << 1;                                 +
   +            else    K2 := (K1 << 1) XOR const_Rb;                  +
   +   Step 4.  return K1, K2;                                         +
   +                                                                   +
		 */
		byte bRb = (byte)0x87; // Rb for AES128
		// key must be 16 bytes
		try
		{
			skeySpec = new SecretKeySpec(key, "AES");
			if (cipher == null)
				cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

			K1 =  cipher.doFinal(Z16);
		}
		catch (Exception ex)  // nosuchalgorithm, invalidkey,nosuchpadding...
		{
			throw new RuntimeException(ex);
		}

		boolean highL = ((K1[0] & 0x80) != 0);
		K1 = shl(K1);
		if (highL)
			K1[15] = (byte)(K1[15] ^ bRb);


		highL =  ((K1[0] & 0x80) != 0);
		K2 = shl(K1);
		if (highL)
			K2[15] = (byte)(K2[15] ^ bRb);

	}
	//♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧
	static byte[] xor16(byte[] ba, byte[] bb)
	{
		byte[] bout = new byte[ba.length];
		for (short j = 0; j < ba.length; j++)
			bout[j] = (byte)(ba[j] ^ bb[j]);
		return bout;
	}


	//♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧♧


	static public byte[] CMAC(byte[] key, byte[] mesg) throws Exception
	{
		/*
         +   Input    : K    ( 128-bit key )                                 +
   +            : M    ( message to be authenticated )                 +
   +            : len  ( length of the message in octets )             +
   +   Output   : T    ( message authentication code )                 +
   +
         +              const_Bsize is 16                                    +
   +                                                                   +
   +   Variables: K1, K2 for 128-bit subkeys                           +
   +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
   +              M_last is the last block xor-ed with K1 or K2        +
   +              n      for number of blocks to be processed          +
   +              r      for number of octets of last block            +
   +              flag   for denoting if last block is complete or not +
   +                                                                   +
   +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
   +   Step 2.  n := ceil(len/const_Bsize);
         The smallest integer no smaller than x.
          ceil(3.5) is 4.  ceil(5) is 5.+
   +   Step 3.  if n = 0                                               +
   +            then                                                   +
   +                 n := 1;                                           +
   +                 flag := false;                                    +
   +            else                                                   +
   +                 if len mod const_Bsize is 0                       +
   +                 then flag := true;  no overflow                              +
   +                 else flag := false;                               +
   +                                                                   +
   +   Step 4.  if flag is true                                        +
   +            then M_last := M_n XOR K1;                             +
   +            else M_last := padding(M_n) XOR K2;                    +
   +   Step 5.  X := const_Zero;                                       +
   +   Step 6.  for i := 1 to n-1 do                                   +
   +                begin                                              +
   +                  Y := X XOR M_i;                                  +
   +                  X := AES-128(K,Y);                               +
   +                end                                                +
   +            Y := M_last XOR X;                                     +
   +            T := AES-128(K,Y);                                     +
   +   Step 7.  return T;                                              +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


		 */
		subKeys(key);  // set K1,K2
		int mz = mesg.length ;
		int n = mz / 16;  // number of 16byte chunks.. if overflow > 0 add 1 to this
		int m = n * 16;
		int v = mz - m; // overflow bytes 0..15
		if (v > 0)
			n++;  // now the "actual" number of chunks  ie ceiling

		byte[] MLast = new byte[16];
		int lastn = ( n-1 ) * 16;  //byte address of lastchunk within mesg
		int lastz = mz -lastn;  // number of bytes to copy to lastchunk
		System.arraycopy(mesg,lastn, MLast,0,lastz);
		if (v == 0)  // no overflow
			MLast = xor16(MLast,K1);
		else
		{
			MLast[lastz] = (byte)0x80;  // this does the padding
			MLast = xor16(MLast,K2);
		}
		//todo: put MLast backk into mesg and do a normal CBC....
		// we should be able to use CBC...    // todo replace with CBC

		byte[] X     = new byte[16];  // zeros by default;
		//BUT updated IV has to be used in next CMAC or encryption
		byte[] plain = new byte[16];


		if (cipher == null)
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);   // spec set in subkeys???


		for (short j = 0 ; j < n-1; j++)
		{
			int jx = j * 16;  // dont do this kind of thing...
			System.arraycopy(mesg,jx, plain,0,16);
			plain = xor16(plain,X);
			X =  cipher.doFinal(plain);
		}
		plain = xor16(MLast,X);
		X =  cipher.doFinal(plain);

		return X;
	}

    //void DES_ecb_encrypt(const_DES_cblock *input, DES_cblock *output, DES_key_schedule *ks, int enc);
    /**
     DES_ecb_encrypt() is the basic DES encryption routine that encrypts or decrypts a single 8-byte DES_cblock in electronic code book (ECB) mode.
     It always transforms the input data, pointed to by input, into the output data, pointed to by the output argument.
     If the encrypt argument is non-zero (DES_ENCRYPT),
     the input (cleartext) is encrypted in to the output (ciphertext) using the key_schedule specified by the schedule argument,
     previously set via DES_set_key. If encrypt is zero (DES_DECRYPT),
     the input (now ciphertext) is decrypted into the output (now cleartext).
     Input and output may overlap. DES_ecb_encrypt() does not return a value.
     * @param edataOffset TODO
     * @param edataOffset TODO
     */

    public static void DES_ecb_encrypt(byte[] data, int dataOffset, byte[] edata, int edataOffset, byte[] ks2, DESType desDecrypt) throws Exception {

        SecretKeySpec key = new SecretKeySpec(ks2, 0, 8, "DES");

        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        if(desDecrypt == DESType.DES_DECRYPT) {
            cipher.init(Cipher.DECRYPT_MODE, key);
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        cipher.update(data, dataOffset, 8, edata, edataOffset);
    }

    public static void DES_set_key(byte[] data, int dataOffset, byte[] output) {
        System.arraycopy(data, dataOffset, output, 0, output.length);
    }

    public static void RAND_bytes(byte[] pCD_RndA, int length) {
        randomSource.fillRandom(pCD_RndA);
    }

}
