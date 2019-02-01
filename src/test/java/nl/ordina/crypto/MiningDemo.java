package nl.ordina.crypto;

import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * A small message digest demo.
 */
public class MiningDemo {

	class Block {
		List<Transaction> transactions = new ArrayList<>();
		int nonce = 0;

		@Override
		public String toString() {
			return "Block{" +
					"transactions=" + transactions +
					", nonce=" + nonce +
					'}';
		}
	}
	class Transaction {

		public Transaction(String from, String to, int amount) {
			this.from = from;
			this.to = to;
			this.amount = amount;
		}

		String from;
		String to;
		int amount;

		@Override
		public String toString() {
			return "Transaction{" +
					"from='" + from + '\'' +
					", to='" + to + '\'' +
					", amount=" + amount +
					'}';
		}
	}
	//1. show hash
	//2. change one letter
	//3. Make the message longer
	//4. Change provider

	@Test
	public void miningDemo() throws NoSuchAlgorithmException {

		//setup block
		Transaction transaction = new Transaction("michel", "jfokus", 10);
		Block block = new Block();
		block.transactions.add(transaction);

		MessageDigest digester = MessageDigest.getInstance("SHA-256");

		while (!(digester.digest(block.toString().getBytes())[0] == 0)) {
			System.out.println("block" + block + " has hash " + Hex.encodeHexString(digester.digest(block.toString().getBytes())) + ", not good enough!");
			block.nonce++;
		}

		System.out.println("block" + block + " has hash " + Hex.encodeHexString(digester.digest(block.toString().getBytes())));
		System.out.println("block took " + block.nonce + " iterations to seal.");

	}

}
