/**********************************************************************************/
/* BitcoinRandomGen.java                                                          */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a probabalistic verification method for the iterated
   hash function used in BitcoinRandomGen.java. While the hash function may be computationally
   expensive to compute, we can easily verify a small segment of it. Our
   getProbabalisticVerification method takes a byte[][] corresponding to hash-checkpoints of our
   iterated hash, and randomly selects one checkpoint to verify. It returns 1 followed by the index
   verified if the following checkpoint index correctly follows from the selected index. It returns
   -1 following by the fraudulant index otherwise.

/* USAGE:    mvn exec:java -Dexec.args="447430"    */
/* ------------------------------------------------------------------------------ */
/* EXAMPLE: [1, 209]                                                              */
/*                                                                                */
/**********************************************************************************/
package info.blockchain.api.blockexplorer;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.util.Random;
public class BitcoinBeaconVerification
{
	public static final int VERIFICAITON_HASH_DISTANCE = BitcoinRandomGen.VERIFICAITON_HASH_DISTANCE;
	public BitcoinBeaconVerification()
	{
	}

	public int[] getProbabalisticVerification(byte[][] becresult)
	{
		int numhashes = becresult.length;
		Random rand = new Random();
		int ranhash = rand.nextInt(numhashes - 1);
		byte[] nextcheckpoint = becresult[ranhash];
		PRF prf = new PRF(becresult[0]);
		int[] result = new int[2];

		for (int i = 0; i < VERIFICAITON_HASH_DISTANCE; i++)
		{
			nextcheckpoint = prf.eval(nextcheckpoint);
		}

		result[1] = ranhash;
		result[0] = 1;
		for (int i = 0; i < nextcheckpoint.length; i++)
		{
			if (nextcheckpoint[i] != becresult[ranhash + 1][i])
			{
				result[0] = -1;
			}
		}
		return result;
	}
}