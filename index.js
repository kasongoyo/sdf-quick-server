'use strict';

require('dotenv').config();
const {Keypair, Transaction, Networks, Utils, StrKey, Server} = require('stellar-sdk');
const createError = require('http-errors');
const jwt = require('jsonwebtoken');

const SIGNING_KEY = process.env.SIGNING_KEY;
const SIGNING_SEED = process.env.SIGNING_SEED;

let randomKeyPair = Keypair.random();
const server = new Server('https://horizon.stellar.org');
const serverKeypair = Keypair.fromSecret(SIGNING_SEED);

const NETWORK = Networks.PUBLIC;
const resolve = (promise) => {
    return promise.then(data => {
        return [null, data];
    })
        .catch(err => [err]);
}
/**
 * 
 *  Generate the challenge transaction for a client account.
 *  This is used in `GET <auth>`, as per SEP 10.
 *  @param account {string} - client account 
 *  @returns {string} Returns the XDR encoding of that transaction.
 *  
 */
const getChallengeTransaction = (account) => {
    if (!account) {
        const error = new createError.BadRequest('The stellar account to be authenticated must be provided');
        return Promise.reject(error)
    }
    if (!StrKey.isValidEd25519PublicKey(account)) {
        const error = new createError.BadRequest('Invalid stellar account provided');
        return Promise.reject(error)
    }

    const challenge = Utils.buildChallengeTx(serverKeypair, account, 'ClickPesa', 300, NETWORK)
    return Promise.resolve({ transaction: challenge });
};
/**
 * From Sep 10 doc
 * This fn checks the follwings 
 * If the user's account exists:
 * The server gets the signers of the user's account
 * The server verifies the client signatures count is one or more;
 * The server verifies the client signatures on the transaction are signers of the user's account;
 * The server verifies the weight provided by the signers meets the required threshold(s), if any
 */
const validateChallenge = async (challengeTx) => {
    if (!challengeTx) {
        const error = new createError.BadRequest('Invalid signed challenge');
        return Promise.reject(error)
    }
    const { tx, clientAccountID } = Utils.readChallengeTx(challengeTx, SIGNING_KEY, NETWORK);
    const [loadExistErr, account] = await resolve(server.loadAccount(clientAccountID));
    if (loadExistErr) {
        Utils.verifyChallengeTxSigners(challengeTx, SIGNING_KEY, NETWORK, [clientAccountID]);
        if (tx.signatures.length !== 2) {
            throw createError(400, "There is more than one client signer on a challenge")
        }
    } else {
        const threshold = account.thresholds.med_threshold;
        const signerSummary = account.signers;
        Utils.verifyChallengeTxThreshold(challengeTx, SIGNING_KEY, NETWORK, threshold, signerSummary);
    }
    const issuedAt = (new Date()).getTime() / 1000;
    const expiredAt = issuedAt + (24 * 60 * 60);
    const payload = {
        "sub": clientAccountID,
        "iat": issuedAt,
        "exp": expiredAt,
        "jti": tx.hash(),
    };
    const token = jwt.sign(payload, 'clickpesa');
    return { token };
}


const auth = () => {
    getChallengeTransaction(randomKeyPair.publicKey())
        .then(result => {
            const unfundedTx = result.transaction;
            return unfundedTx;
        })
        .then(unfundedTx => {
            const tx = new Transaction(unfundedTx, Networks.PUBLIC);
            tx.sign(randomKeyPair)
            const txSigned = tx.toXDR();
            return validateChallenge(txSigned)
        })
        .then(({ token }) => {
            console.log(token);
        });
}

auth();
