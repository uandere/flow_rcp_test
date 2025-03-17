use futures::StreamExt;
use rlp::RlpStream;
use secp256k1::{Message, Secp256k1, SecretKey};
use sha3::{Digest, Sha3_256 as Sha256};
use std::time::Duration;
use tokio::select;
use tonic::{Request, transport::Channel};

// Import the generated Flow protobuf modules
extern crate prost_types;

mod flow {
    pub mod access {
        tonic::include_proto!("flow.access");
    }

    pub mod entities {
        tonic::include_proto!("flow.entities");
    }

    pub mod execution {
        tonic::include_proto!("flow.execution");
    }

    pub mod executiondata {
        tonic::include_proto!("flow.executiondata");
    }
}

use flow::access::access_api_client::AccessApiClient as AccessClient;
use flow::access::{
    GetAccountRequest, GetLatestBlockRequest, SendAndSubscribeTransactionStatusesRequest,
};
use flow::entities::{Transaction, transaction};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum TransactionStatus {
    Unknown = 0,
    Pending = 1,
    Finalized = 2,
    Executed = 3,
    Sealed = 4,
    Expired = 5,
}

impl TransactionStatus {
    fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(TransactionStatus::Unknown),
            1 => Some(TransactionStatus::Pending),
            2 => Some(TransactionStatus::Finalized),
            3 => Some(TransactionStatus::Executed),
            4 => Some(TransactionStatus::Sealed),
            5 => Some(TransactionStatus::Expired),
            _ => None,
        }
    }
}

// Domain tag for Flow transaction signing
const TRANSACTION_DOMAIN_TAG: &str =
    "464c4f572d56302e302d7472616e73616374696f6e0000000000000000000000";

const MAX_WAIT_TIME: Duration = Duration::from_secs(60); // Maximum wait time (60 seconds)

/// Print debug information about an account's key
fn print_account_key_debug(account: &flow::entities::Account, key_index: u32) {
    if let Some(key) = account.keys.get(key_index as usize) {
        println!("=== Account Key Debug ===");
        println!("Key Index: {}", key_index);
        println!("Public Key (hex): {}", hex::encode(&key.public_key));
        println!("Hash Algorithm: {}", key.hash_algo);
        println!("Signature Algorithm: {}", key.sign_algo);
        println!("Sequence Number: {}", key.sequence_number);
        println!("Revoked: {}", key.revoked);
        println!("Weight: {}", key.weight);
        println!("========================");
    } else {
        println!("❌ No key found at index {}", key_index);
    }
}

/// Print debug information about the derived public key
fn print_public_key_debug(private_key: &SecretKey) {
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);

    println!("=== Derived Public Key Debug ===");
    println!(
        "Public Key (compressed): {}",
        hex::encode(public_key.serialize())
    );
    println!("Private key: {}", private_key.display_secret().to_string());
    println!(
        "Public Key (uncompressed): {}",
        hex::encode(public_key.serialize_uncompressed())
    );
    println!("==============================");
}

/// Enhanced transaction hash debug
fn print_transaction_hash_debug(tx: &Transaction) {
    let hash = hash_transaction(tx);

    println!("=== Transaction Hash Debug ===");
    println!("Domain Tag: {}", TRANSACTION_DOMAIN_TAG);
    println!(
        "Script (first 50 bytes): {}",
        hex::encode(&tx.script)
    );
    println!("Arguments Count: {}", tx.arguments.len());
    println!(
        "Reference Block ID: {}",
        hex::encode(&tx.reference_block_id)
    );
    println!("Gas Limit: {}", tx.gas_limit);

    if let Some(pk) = &tx.proposal_key {
        println!("Proposal Key Address: {}", hex::encode(&pk.address));
        println!("Proposal Key ID: {}", pk.key_id);
        println!("Proposal Key Sequence Number: {}", pk.sequence_number);
    }

    println!("Payer: {}", hex::encode(&tx.payer));
    println!("Authorizers: {}", tx.authorizers.len());
    for (i, auth) in tx.authorizers.iter().enumerate() {
        println!("  Authorizer {}: {}", i, hex::encode(auth));
    }

    println!("Final Hash (SHA3-256): {}", hex::encode(&hash));
    println!("============================");
}

/// Enhanced signature debug
fn print_signature_debug(
    hash: &[u8],
    signature: &secp256k1::ecdsa::Signature,
    private_key: &SecretKey,
) {
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);
    let message = Message::from_digest(<[u8; 32]>::try_from(hash).unwrap());

    println!("=== Signature Debug ===");
    println!("Message to sign (hash): {}", hex::encode(hash));
    println!(
        "Signature R value: {}",
        hex::encode(&signature.serialize_compact()[..32])
    );
    println!(
        "Signature S value: {}",
        hex::encode(&signature.serialize_compact()[32..])
    );
    println!(
        "Signature (compact, 64 bytes): {}",
        hex::encode(signature.serialize_compact())
    );
    println!(
        "Signature (DER format): {}",
        hex::encode(signature.serialize_der())
    );

    // Verify the signature
    let verification_result = secp.verify_ecdsa(&message, signature, &public_key);
    println!("Local signature verification: {}", &{
        match verification_result {
            Ok(_) => "✅ Valid".to_string(),
            Err(e) => format!("❌ Invalid: {}", e).to_string(),
        }
    });

    println!("======================");
}

/// Convert hex string to byte vector
fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let clean_hex = hex_str.trim_start_matches("0x");
    Ok(hex::decode(clean_hex)?)
}

/// Parse a secp256k1 private key from hex string
fn parse_private_key(private_key_hex: &str) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let key_bytes = hex_to_bytes(private_key_hex)?;
    let secret_key = SecretKey::from_slice(&key_bytes)?;
    Ok(secret_key)
}

/// Get account details by address
async fn get_account(
    client: &mut AccessClient<Channel>,
    address: Vec<u8>,
) -> Result<flow::entities::Account, Box<dyn std::error::Error>> {
    let request = Request::new(GetAccountRequest { address });

    let response = client.get_account(request).await?;
    let account = response.into_inner().account.ok_or("No account returned")?;

    Ok(account)
}

/// Get the latest block ID to use as reference block
async fn get_reference_block_id(
    client: &mut AccessClient<Channel>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let request = Request::new(GetLatestBlockRequest {
        full_block_response: false,
        is_sealed: true,
    });

    let response = client.get_latest_block(request).await?;
    let block = response.into_inner().block.ok_or("No block returned")?;

    Ok(block.id)
}

/// Calculate the hash of a transaction for signing using RLP encoding and SHA3-256
fn hash_transaction(tx: &Transaction) -> Vec<u8> {
    // Use SHA3-256 instead of SHA2-256
    let mut hasher = Sha256::new();

    // Add domain tag
    hasher.update(hex_to_bytes(TRANSACTION_DOMAIN_TAG).unwrap());

    // Use RLP encoding to ensure canonical format
    let mut rlp: RlpStream = RlpStream::new_list(2);
    rlp.begin_list(9); // Transaction has 9 fields

    // 1. Script
    rlp.append(&tx.script);

    // 2. Arguments
    rlp.begin_list(tx.arguments.len());
    for arg in &tx.arguments {
        rlp.append(&arg.as_slice());
    }

    // 3. Reference Block ID
    rlp.append(&tx.reference_block_id);

    // 4. Gas Limit
    rlp.append(&tx.gas_limit);

    // 5. Proposal Key
    if let Some(pk) = &tx.proposal_key {
        // No need to begin a list here as per the fix
        rlp.append(&pk.address);
        rlp.append(&pk.key_id);
        rlp.append(&pk.sequence_number);
    } else {
        rlp.begin_list(0);
    }

    // 6. Payer
    rlp.append(&tx.payer);

    // 7. Authorizers
    rlp.begin_list(tx.authorizers.len());
    for auth in &tx.authorizers {
        rlp.append(&auth.as_slice());
    }

    // 8. Payload Signatures
    rlp.begin_list(tx.payload_signatures.len());
    for sig in &tx.payload_signatures {
        rlp.begin_list(3);
        rlp.append(&sig.address);
        rlp.append(&sig.key_id);
        rlp.append(&sig.signature);
    }

    // 9. Envelope Signatures (not included in the hash)
    // Removed as per diff

    // Finish RLP encoding
    let encoded = rlp.out();

    println!("RLP encoded: {}", hex::encode(encoded.clone()));

    // Hash the encoded transaction with SHA3-256
    hasher.update(&encoded);

    // Return the hash
    hasher.finalize().to_vec()
}

/// Sign a transaction with the given secp256k1 private key
fn sign_transaction(
    tx: &mut Transaction,
    signer_address: &[u8],
    key_index: u32,
    private_key: &SecretKey,
    account: &flow::entities::Account, // Add account parameter for debugging
) -> Result<(), Box<dyn std::error::Error>> {
    // Print account key information for debugging
    print_account_key_debug(account, key_index);

    // Print derived public key information
    print_public_key_debug(private_key);

    // Print transaction details for debugging
    print_transaction_hash_debug(tx);

    // Calculate the transaction hash
    let hash = hash_transaction(tx);

    // Create a Secp256k1 context
    let secp = Secp256k1::new();

    fn vec_to_array(vec: Vec<u8>) -> Result<[u8; 32], &'static str> {
        // Ensure the Vec has exactly 32 elements
        if vec.len() != 32 {
            return Err("Vec length must be 32");
        }
        // Convert to array (infallible after length check)
        Ok(vec.try_into().unwrap_or_else(|_| unreachable!()))
    }

    // Create a message from the hash
    let message = Message::from_digest(vec_to_array(hash.clone()).unwrap());

    println!("Message to sign: {}", hex::encode(&message[..]));

    // Sign the message
    let signature = secp.sign_ecdsa(&message, private_key);

    // Print signature debug information
    print_signature_debug(&hash, &signature, private_key);

    // Get the signature in compact format (64 bytes, R+S)
    let signature_bytes = signature.serialize_compact().to_vec();

    // Create a signature envelope
    let envelope_signature = transaction::Signature {
        address: signer_address.to_vec(),
        key_id: key_index,
        signature: signature_bytes,
    };

    // Add the signature to the envelope signatures
    tx.envelope_signatures.push(envelope_signature);

    Ok(())
}

/// Send a transaction and subscribe to status updates
pub async fn send_transaction_and_subscribe(
    client: &mut AccessClient<Channel>,
    transaction: Transaction,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Subscribe to transaction status updates
    let request = Request::new(SendAndSubscribeTransactionStatusesRequest {
        event_encoding_version: 1,
        transaction: Some(transaction),
    });

    let mut stream = client
        .send_and_subscribe_transaction_statuses(request)
        .await?
        .into_inner();

    // Set up a timeout for the subscription
    let timeout = tokio::time::sleep(MAX_WAIT_TIME);

    tokio::pin!(timeout);

    loop {
        select! {
            // Wait for the next status update or timeout
            result = stream.next() => {
                match result {
                    Some(Ok(status_response)) => {
                        if let Some(response) = status_response.transaction_results {
                            let status = TransactionStatus::from_i32(response.status)
                                .unwrap_or(TransactionStatus::Unknown);

                            println!("Transaction status update: {:?}", status);

                            match status {
                                TransactionStatus::Sealed => {
                                    println!("Transaction sealed successfully!");
                                    return Ok(response.transaction_id);
                                }
                                TransactionStatus::Expired => {
                                    return Err("Transaction expired".into());
                                }
                                // Continue waiting for other statuses
                                _ => continue,
                            }
                        } else {
                            println!("Received status update with no transaction results");
                            continue;
                        }
                    }
                    Some(Err(e)) => {
                        return Err(format!("Error from transaction status stream: {}", e).into());
                    }
                    None => {
                        return Err("Transaction status stream closed unexpectedly".into());
                    }
                }
            }
            // Handle timeout
            _ = &mut timeout => {
                return Err("Maximum wait time exceeded".into());
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to the Flow Testnet Access API
    let channel = Channel::from_static("http://access.testnet.nodes.onflow.org:9000")
        .connect()
        .await?;

    let mut client = AccessClient::new(channel);

    // Set your Flow account address and private key
    let account_address_hex = "788db9ec197a75de"; // Without 0x prefix
    let private_key_hex = "3b75e9e624b7aec74181c37270296fe4718af0f674012758df99e59ab0f85b50"; // Your private key

    // Convert address from hex
    let account_address = hex_to_bytes(account_address_hex)?;

    // Parse the private key (as secp256k1 key)
    let private_key = parse_private_key(private_key_hex)?;

    // Get account information to retrieve the latest sequence number
    let account = get_account(&mut client, account_address.clone()).await?;

    // Use the first key (index 0)
    let key_index = 0u32;

    // Get the current sequence number for the key
    let sequence_number = account
        .keys
        .get(key_index as usize)
        .ok_or("No key found at the specified index")?
        .sequence_number;

    println!(
        "Account retrieved. Current sequence number: {}",
        sequence_number
    );

    // Get latest block ID for reference
    let reference_block_id = get_reference_block_id(&mut client).await?;
    println!("Reference block ID: {}", hex::encode(&reference_block_id));

    // Create the transaction
    let mut transaction = Transaction {
        script: r#"
            transaction {
                prepare(signer: &Account) {
                    log("Transaction executed")
                }
                execute {
                    log("Hello from Flow!")
                }
            }
        "#
            .as_bytes()
            .to_vec(),
        arguments: vec![],
        reference_block_id,
        gas_limit: 100,
        proposal_key: Some(transaction::ProposalKey {
            address: account_address.clone(),
            key_id: key_index,
            sequence_number: sequence_number.into(),
        }),
        payer: account_address.clone(),
        authorizers: vec![account_address.clone()],
        payload_signatures: vec![],
        envelope_signatures: vec![],
    };

    // Sign the transaction with secp256k1 and SHA3-256
    // Pass the account for debugging purposes
    sign_transaction(
        &mut transaction,
        &account_address,
        key_index,
        &private_key,
        &account,
    )?;

    println!("Transaction signed. Sending to network...");

    // Send transaction and subscribe to status updates
    let tx_id = send_transaction_and_subscribe(&mut client, transaction).await?;
    println!("Transaction with ID {} is sealed", hex::encode(&tx_id));

    Ok(())
}