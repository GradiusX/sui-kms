import { Secp256k1PublicKey } from '@mysten/sui.js';
import { KMSClient, GetPublicKeyCommand, SignCommand, MessageType, AlgorithmSpec, SigningAlgorithmSpec } from "@aws-sdk/client-kms";
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import EthCrypto from 'eth-crypto';
var asn1 = require('asn1.js');

const _accessKeyId = "<AWS ACCESS KEY>"
const _secretAccessKey = "<AWS SECRET ACCESS KEY>"
const _sessionToken = "<AWS SESSION TOKEN"
const kmsKeyId = "<AWS KMS KEY ID>"
const kmsRegion = "<AWS REGION>"

// Initiate KMS Client
const kmsClient = new KMSClient({
  region: kmsRegion, 
  credentials: {
	accessKeyId: _accessKeyId,
	secretAccessKey: _secretAccessKey,
	sessionToken: _sessionToken
  }
});

// Sign a msg with KMS (MessageType: RAW | DIGEST)
async function signWithKMS(msg: Uint8Array, mgs_type: MessageType) {
    const input = {
        KeyId: kmsKeyId, 
        Message: msg,
        SigningAlgorithm: SigningAlgorithmSpec.ECDSA_SHA_256,
        MessageType: mgs_type
    };
    const command = new SignCommand(input);
	const response = await kmsClient.send(command);
	return response.Signature
}


// Definition of EcdsaPubKey
const EcdsaPubKey = asn1.define('EcdsaPubKey', function(this: any) {
    // https://tools.ietf.org/html/rfc5480#section-2
    this.seq().obj(
        this.key('algo').seq().obj(
            this.key('algorithm').objid(),
            this.key('parameters').objid(),
        ),
        this.key('pubKey').bitstr()
    );
});

// Obtain compressed public key from KMS
async function getKMSPublicKey() {
	const params = {
		KeyId: kmsKeyId
	};
	const command = new GetPublicKeyCommand(params);
	const pk_full_raw = await kmsClient.send(command);
	const pk_raw = pk_full_raw.PublicKey!
    const res = EcdsaPubKey.decode(Buffer.from(pk_raw), "der");
    const kms_pk_comp = EthCrypto.publicKey.compress(res.pubKey.data)
    return Uint8Array.from(Buffer.from(kms_pk_comp, 'hex'))
}

// GET Sui Public Address from AWS KMS Public Key
async function getSuiAddressFromKMSPublicKey(){
    const kms_pk_compressed = await getKMSPublicKey()   
    const secp256k1_pk =  new Secp256k1PublicKey(kms_pk_compressed)
    const suiAddress = secp256k1_pk.toSuiAddress()
    return suiAddress
}


// This function already exists in library-sui
// https://github.com/fireflyprotocol/library-sui/blob/22b54b519ec4c99ac796e7149162b4fa5b374646/src/classes/OrderSigner.ts#L211
function verifySECP(
    signature: string,
    data: Uint8Array,
    publicKey: Uint8Array
): boolean {
    const sig_r_s = secp256k1.Signature.fromCompact(signature);
    const sig_r_s_b1 = sig_r_s.addRecoveryBit(0x1);
    const recovered_pk_1 = sig_r_s_b1
        .recoverPublicKey(data)
        .toRawBytes(true)
        .toString();

    const sig_r_s_b0 = sig_r_s.addRecoveryBit(0x0);
    const recovered_pk_0 = sig_r_s_b0
        .recoverPublicKey(data)
        .toRawBytes(true)
        .toString();

    return (
        publicKey.toString() === recovered_pk_1 ||
        publicKey.toString() === recovered_pk_0
    );
}

(async () => {

    ////// Obtain Sui Public Address ////////
    const suiAddress = await getSuiAddressFromKMSPublicKey()
    console.log("Sui Wallet Address ", suiAddress)

    // Sign a msg with KMS and compress the resultant signature
	const msg = Buffer.from('hello world2', 'utf8').toString('hex');
    const msgHash = sha256(msg);
    const sig_DER = await signWithKMS(msgHash, 'DIGEST')
    const sig_r_s = secp256k1.Signature.fromDER(Buffer.from(sig_DER).toString('hex'))
    const sig = sig_r_s.normalizeS().toCompactHex()

    // Get uncompressed Public Key from KMS
    const kms_pk = await getKMSPublicKey()
  
    // verify our working with library-sui's method
    if (verifySECP(sig,msgHash, kms_pk )){
        console.log("Successful Comparison")
    }
    else{
        console.log("Rubbish")
    }
})()