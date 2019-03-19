import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */


    private UTXOPool utxopool;
    private double input_sum;

    public TxHandler(UTXOPool utxoPool) {
         this.utxopool = new UTXOPool(utxoPool);
         this.input_sum = 0;
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {

        return test1(tx) && test2(tx);
    }


    private boolean test1(Transaction tx)
    {   
        //stores the map of already used or consumed utxo
        HashMap<UTXO, Boolean> usedUTXO = new HashMap<UTXO, Boolean>();

        int num_inputs = tx.numInputs();

        for(int i=0;i<num_inputs;i++)
        {
            Transaction.Input ip = tx.getInput(i);

            if(ip == null)
            {
                return false;
            }

            UTXO utxo = new UTXO(ip.prevTxHash,ip.outputIndex);

            //check is coin is available
            //if not available, return false
            if(this.utxopool.contains(utxo) == false)
            {
                return false;
            }

            Transaction.Output prevTxOutput = this.utxopool.getTxOutput(utxo);

            //check if the output is not null
            if(prevTxOutput == null)
            {
                return false;
            }

            //check if the signature is valid
            PublicKey public_key = prevTxOutput.address;
            byte[] msg = tx.getRawDataToSign(i);
            byte[] signature = ip.signature;

            if(Crypto.verifySignature(public_key,msg,signature) == false)
            {
                return false;
            }

            //check if this input is already used
            if(usedUTXO.containsKey(utxo) == true)
            {
                return false;
            }

            this.input_sum += prevTxOutput.value;

        }

        return true;

    }


    private boolean test2(Transaction tx)
    {
        //check if input sum is greater than or equal to output sum

        double outptut_sum = 0;

        for(int i=0;i<tx.numOutputs();i++)
        {
            Transaction.Output op = tx.getOutput(i);
            if(op == null)
            {
                return false;
            }

            if(op.value < 0)
            {
                return false;
            }

            outptut_sum += op.value;
        }

        if(this.input_sum >= outptut_sum)
        {
            return true;
        }

        return false;
    }

    
    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        // IMPLEMENT THIS

       if(possibleTxs == null)
       {
            return new Transaction[0];
       }

       ArrayList<Transaction> valid_transactions = new ArrayList<>();

       for(int i=0;i<possibleTxs.length;i++)
       {
            Transaction tx = possibleTxs[i];

            if(isValidTx(tx) == false)
            {
                continue;
            }

            valid_transactions.add(tx);

            int num_inputs = tx.numInputs();

            for(int j=0;j<num_inputs;j++)
            {
                Transaction.Input ip = tx.getInput(j);

                UTXO utxo = new UTXO(ip.prevTxHash,ip.outputIndex);
                this.utxopool.removeUTXO(utxo);
            }

            byte[] tx_hash = tx.getHash();
            int num_outputs = tx.numOutputs();

            for(int j =0;j<num_outputs;j++)
            {
                Transaction.Output op = tx.getOutput(j);

                UTXO utxo = new UTXO(tx_hash,j);
                this.utxopool.addUTXO(utxo,op);
            }
       }

       return valid_transactions.toArray(new Transaction[valid_transactions.size()]);
    }

}
