/**********************************************************************************/
/* BitcoinRandomGen.java                                                          */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a random number generator via the blockchain*/
/* We create a BitCoinRandomGen Object which has a next method taking an integer  */
/* argument n, and returns a random byte array associated with the block of height n on the blockchain, */
/* obtained by creating a PRF with key equal to the block's merkle root, and evaluated on the block's */
/* nonce 
/* USAGE:  */         
/* ------------------------------------------------------------------------------ */
/* EXAMPLE:                                                                       */
/*                                                                                */
/**********************************************************************************/
package test;

import info.blockchain.api.blockexplorer.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
public class BitcoinRandomGen
{
	public BitcoinRandomGen()
	{
	}

	public static byte[] getRandomAtHeight(long tarheight)
	{
		BlockExplorer bexp = new BlockExplorer();
		LatestBlock curblock;
		try {
			curblock = bexp.getLatestBlock();
		}
		catch (Exception e)
		{
			System.out.println("Server error");
			return null;
		}
		long curheight = curblock.getHeight();
		while (curheight != tarheight)
		{
			try {
			curblock = bexp.getLatestBlock();
			}
			catch (Exception e)
			{
				System.out.println("Server error");
				return null;
			}
			curheight = curblock.getHeight();
		}

		// Now our curblock should be the target block
		Block tarblock;
		try {
			tarblock = bexp.getBlock(curblock.getHash());
		}
		catch (Exception e)
		{
			System.out.println("Server error");
			return null;
		}
		String merkle = tarblock.getMerkleRoot();
		byte[] key = merkle.getBytes(StandardCharsets.UTF_8);
		PRF prf = new PRF(key);
		long nonce = tarblock.getNonce();
		byte[] noncebytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(nonce).array();
		return prf.eval(noncebytes);
	}

	public static void main(String[] args)
	{
		long n = Long.parseLong(args[0]);
		System.out.println(BitcoinRandomGen.getRandomAtHeight(n));
	}
}