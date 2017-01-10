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
public class BitcoinRandomGen
{
	public static final int HASH_ITERATIONS = 1000000;
	public static final int PROBABALISTIC_VERIFICATION_CHECKPOINTS = (HASH_ITERATIONS / 1000) + 1;
	public static final int VERIFICAITON_HASH_DISTANCE = HASH_ITERATIONS / 1000;
	public BitcoinRandomGen()
	{
	}

	public static byte[][] getRandomVerificationAtHeight(long tarheight)
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
			System.out.println(curheight);
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

		long time = tarblock.getTime();
		byte[] timebytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(time).array();

		prf.update(timebytes);
		byte[][] beaconresult = new byte[PROBABALISTIC_VERIFICATION_CHECKPOINTS][];
		beaconresult[0] = prf.eval(noncebytes);
		PRF seedprf = new PRF(beaconresult[0]);
		// at this point the beacon seed should be dependant on the merkle root, nonce, and time of target block.
		byte[] tempbeacon = beaconresult[0];
		// Iterative hash function to make hash computationally expensive to promote security properties

		int counter = VERIFICAITON_HASH_DISTANCE;
		for (int x = 1; x <= HASH_ITERATIONS; x++)
		{
			tempbeacon = seedprf.eval(tempbeacon);
			if (x == counter)
			{
				beaconresult[counter / VERIFICAITON_HASH_DISTANCE] = tempbeacon;
				counter += VERIFICAITON_HASH_DISTANCE;
			}
		}
		return beaconresult;

	}

	public static void main(String[] args)
	{
		System.out.println("Probabalistic verification checkpoints: " + PROBABALISTIC_VERIFICATION_CHECKPOINTS);
		System.out.println("Verification Distance:" + VERIFICAITON_HASH_DISTANCE);

		long targetheight = Long.parseLong(args[0]);
		byte[][] checklist = BitcoinRandomGen.getRandomVerificationAtHeight(targetheight);
		byte[] result = checklist[PROBABALISTIC_VERIFICATION_CHECKPOINTS - 1];
		System.out.println(Arrays.toString(result));

		BitcoinBeaconVerification bitbecverification = new BitcoinBeaconVerification();
		int[] verif = bitbecverification.getProbabalisticVerification(checklist);
		System.out.println(Arrays.toString(verif));
	}
}