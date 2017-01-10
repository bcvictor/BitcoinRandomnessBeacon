/**********************************************************************************/
/* BitcoinRandomGen.java                                                          */
/* ------------------------------------------------------------------------------ */
/* DESCRIPTION: This class implements a random number generator via the blockchain*/
/* We create a BitCoinRandomGen Object which has a next method taking an integer  */
/* argument n, and returns a random byte array associated with the block of height n on the blockchain, */
/* obtained by creating a PRF with key equal to the block's merkle root, and evaluated on the block's */
/* nonce and time. This PRF will be iterated on itself many times, and the final output will be returned.




NOTE: There is an issue of an attacker bribing miners the block reward to suppress unfavorable blocks.
We try and solve by making hash function very expensive so that by the time a malicious miner determines a block
to be either favorable or unfavorable, another block has been published and the malicious miner cannot modify the
beacon. We do this by making the beacon output the result of an iterative hash function (HmacSHA256), which will
undergo as many hash iterations as is necessary to make sure that an ASIC  chip (CPU that solves iterative hash 
the fastest) takes 15 minutes (5 more than average block time of 10 minutes) to preform the iterative hash. This
allows a good-willed entity like NIST to publish beacon values for given blocks with a relatively minor software
investment of an ASIC chip, and the miners (with considerably more computing power) cannot outpreform this single
ASIC chip as the iterative hash function is a non-parallelizable / sequential algorithm, and thus a million ASIC
chips should not outpreform a single one.

NOTE: Split into primary verification-randomgen, returns 2d byte arrow containing hash value at every 100,000 hashes
so that normal users can probabalistically verify. Child function no-verification-randomgen which only calls actual
function and returns the last byte array (actual output of beacon).

/* USAGE:    mvn exec:java -Dexec.args="477400"      */
/* ------------------------------------------------------------------------------ */
/* EXAMPLE: [14, 32, 105, -61, 37, -41, 43, 52, 76, -4, -5, -29, 68, -85, -47, 65, 
-98, 82, -108, 46, -119, 83, -84, -106, -70, 53, 61, 13, 90, -87, 67, -15]                                                                      */
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