package nl.ordina.crypto;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class BitcoinTransactionSigningDemo {

    class Transaction {

        public Transaction(String from, String to, int amount) {
            this.from = from;
            this.to = to;
            this.amount = amount;

        }

        String from;
        String to;
        int amount;
        String signature;

        @Override
        public String toString() {
            return "Transaction{" +
                    "\nfrom='" + from + '\'' +
                    "\n, to='" + to + '\'' +
                    "\n, amount=" + amount +
                    "\n, signature=" + signature +
                    '}';
        }
    }

    @Test
    public void testAsymmetricSigningWithSignatureClasses() throws GeneralSecurityException, DecoderException {

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA");
        kpGen.initialize(1024);
        KeyPair michelKeyPair = kpGen.generateKeyPair();
        KeyPair javaZoneKeyPair = kpGen.generateKeyPair();

        Transaction transaction = new Transaction(
                Hex.encodeHexString(michelKeyPair.getPublic().getEncoded()),
                Hex.encodeHexString(javaZoneKeyPair.getPublic().getEncoded()),
                5);

        String data = transaction.from + transaction.to + transaction.amount;

        // create signature
        Signature signatureAlgorithm = Signature.getInstance("SHA256WithRSA");
        signatureAlgorithm.initSign(michelKeyPair.getPrivate());
        signatureAlgorithm.update(data.getBytes());
        transaction.signature = Hex.encodeHexString(signatureAlgorithm.sign());

        System.out.println(transaction);

        Hex.decodeHex(transaction.from);
        // validation of signature

        Signature verificationAlgorithm = Signature.getInstance("SHA256WithRSA");
        verificationAlgorithm.initVerify(constructkey(transaction.from));
        verificationAlgorithm.update(data.getBytes());
        boolean matches = verificationAlgorithm.verify(Hex.decodeHex(transaction.signature));
        System.out.println("signature matches: " + matches);

    }

    private PublicKey constructkey(String keyString) throws NoSuchAlgorithmException, InvalidKeySpecException, DecoderException {
        byte[] publicKeyArray = Hex.decodeHex(keyString);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec X509publicKey = new X509EncodedKeySpec(publicKeyArray);
        return kf.generatePublic(X509publicKey);

    }
}
