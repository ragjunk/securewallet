const bip39 = require('bip39');
const SHA256 = require("js-sha256");
const sss = require('shamirs-secret-sharing');
const Cryptr = require('cryptr');

module.exports = class SecureWallet {
    constructor() {
        this.mnemonic = null;       // BIP39 seed phrases.
        this.recoveryQAs = [];      // Questions and Answers for wallet recovery.
    }
    
    /**
     * Creates a new wallet for the specified email address.
     * @param emailAddress - Email address used to associate the wallet with. 
     * @param recoveryQAs - A list of question and answers to encrypt the wallet's seef phrases.
     * @param threshold - Number of answers required to recover seed phrases.
     * @returns Encrypted safe response. This data can be safely stored anywhere convenient.
     */
    
    createNewWallet(emailAddress, recoveryQAs, threshold) {
        if (!Array.isArray(recoveryQAs) || recoveryQAs.length === 0) {
            throw new Error('Recovery Q&As must be a non-zero array of questions and answers.')
        }
        
        if (recoveryQAs.length <= threshold) {
            throw new Error('Recovery Q&As array length must be larger than the threshold.')
        }
        
        // Step 1: Generate BIP 39 seed phrases for the new wallet.
        this.mnemonic = bip39.generateMnemonic();   
        
        console.log('\nMnemonic:'); console.log(this.mnemonic);
        
        // Step 2: Create Shamir Secret Sharing for the mnemonic.
        const secret = Buffer.from(this.mnemonic);
        const shares = sss.split(secret, { shares: recoveryQAs.length, threshold: threshold });
                
        let safeResponse = {questions: {}, answers: {}};
        
        //console.log('\nShares (Before encryption):'); console.log(shares);
        
        // Step 3: Encrypt each share above with the answers in the recoveryQAs.
        for (let share = 0, qaLength = recoveryQAs.length; share < qaLength; share++) {
            //console.log('\n------ ' + share);
            //console.log('\nOriginal Share:'); console.log(shares[share].toString('hex'));
            
            const cryptr = new Cryptr(recoveryQAs[share].answer.toLocaleLowerCase());
            const encryptedShare = cryptr.encrypt(shares[share].toString('hex'));
                        
            safeResponse.questions['Q'+share] = recoveryQAs[share].question;
            safeResponse.answers['A'+share] = encryptedShare;
        }
        
        const cryptr = new Cryptr(emailAddress);
        const encryptedSafeResponse = cryptr.encrypt(JSON.stringify(safeResponse).toString('hex'));
        
        console.log('\nEncrypted SafeResponse:'); console.log(encryptedSafeResponse);
        return encryptedSafeResponse;
    }
    
    /**
     * Returns seed phrases. Used for debugging purposes. In production environment,
     * this is harmful!
     */
    get seedPhrases() {
        return this.mnemonic;
    }
    
    /**
     * Restores seed phrases for a wallet from the encrypyed safe response.
     * @param emailAddress - Email address used to associate the wallet with. 
     * @param encryptedSafeResponse - Encrypted safe response obtained while creating the wallet.
     * @param answers - A dictionary of answer index and answer. Answers can be case insensitive.
     * @returns Restored seed phrases, if the answers are correct. 
     */
    restoreWallet(emailAddress, encryptedSafeResponse, answers) {
        if (!encryptedSafeResponse) {
            throw new Error('Encrypted safe response is necessary to recover the wallet.')
        }
        const cryptr = new Cryptr(emailAddress);
        let safeResponse = cryptr.decrypt(encryptedSafeResponse);
        
        safeResponse = JSON.parse(safeResponse);
        //console.log('\nSafeResponse:'); console.log(safeResponse);
        
        let recoveryShares = [];
        
        Object.keys(answers).sort().forEach(key => {
            if (safeResponse.answers[key]) {
                const cryptr = new Cryptr(answers[key].toLocaleLowerCase());
                recoveryShares.push(Buffer.from(cryptr.decrypt(safeResponse.answers[key]), 'hex'));
            }
        })
        
        //console.log('\nRecovery shares:'); console.log(recoveryShares);
        
        const recovered = sss.combine(recoveryShares);
        console.log('\nRecovered mnemonic:'); console.log(recovered.toString());
        
        return recovered.toString();
    }
    
}