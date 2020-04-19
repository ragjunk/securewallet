const expect  = require('chai').expect;
const SecureWallet = require('../wallet');

describe('Secure wallet backup with Shamir\'s secret sharing scheme' , function () { 
    // List of questions and answers. Any 3 of 5 correct answers will unlock the encrypted wallet data.
    const qa = [
        {
            question: 'My favorite book in high school', answer: 'The Great Gatsby'
        },
        {
            question: 'My manager in the second company I worked', answer: 'Rich Slesinger'
        },
        {
            question: 'Second tallest peak I climbed', answer: 'Mount Tallac'
        },
        {
            question: 'The name of the street where my favorite restaurant is', answer: 'Castro'
        },
        {
            question: 'Where did I buy rose for my wife for that day?', answer: 'Dagios Flowers'
        }
    ],
    minimumAnswersToUnlockWalletData = 3;
    
    let seedPhrases, 
        encryptedSafeResponse;
    
    it('should create an encrypted safe response', (done) => {
        const wallet = new SecureWallet();
        
        encryptedSafeResponse = wallet.createNewWallet('a@company.com', qa, minimumAnswersToUnlockWalletData);
        seedPhrases = wallet.seedPhrases;

        expect(encryptedSafeResponse).to.have.length.above(0);
        done();
    });
    
    it('should restore seed phrases from encrypted safe response, if correct answers are provided', (done) => {
        const restoredWallet = new SecureWallet();
        let answers = {'A1': 'rich slesinger', 'A3': 'Castro', 'A4': 'Dagios Flowers' };

        const recoveredSeedPhrases = restoredWallet.restoreWallet('a@company.com', encryptedSafeResponse, answers);

        expect(recoveredSeedPhrases).to.equal(seedPhrases);
        done();
    });
    
    it('should fail to restore seed phrases if number of correct answers is less than the threshold', (done) => {
        const restoredWallet = new SecureWallet();
        let answers = {'A1': 'rich slesinger', 'A3': 'Castro' };

        const recoveredSeedPhrases = restoredWallet.restoreWallet('a@company.com', encryptedSafeResponse, answers);

        expect(recoveredSeedPhrases).to.not.equal(seedPhrases);
        done();
    });
    
    it('should fail to restore seed phrases if wrong answers are provided', (done) => {
        const restoredWallet = new SecureWallet();
        let answers = {'A1': 'Mount Tallac', 'A3': 'The Great Gatsby', 'A4': 'Dagios Flowers' };

        let recoveredSeedPhrases;
        
        try {
            recoveredSeedPhrases = restoredWallet.restoreWallet('a@company.com', encryptedSafeResponse, answers);
        } catch(e) {
            recoveredSeedPhrases = null;
        }

        expect(recoveredSeedPhrases).to.not.equal(seedPhrases);
        done();
    });
    
});