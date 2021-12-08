use async_std::{
    net::{TcpListener,
        TcpStream,
    },
    task,
};

use std::{
    sync::{Arc, Mutex},
    net::SocketAddr,
    borrow::Cow,
    io::{
        Error as IoError,
        ErrorKind
    }
};

use futures::{
    pin_mut,
    future,
    channel::mpsc::{unbounded},
    StreamExt,
    TryStreamExt,
    SinkExt,
    channel::mpsc::{UnboundedSender},
};
use async_tungstenite::tungstenite::protocol::Message;
use async_tungstenite::tungstenite::Error as TungsteniteError;

use sodiumoxide::crypto::box_::{PublicKey as SodiumPublicKey, Nonce as SodiumNonce};
use sodiumoxide::crypto::box_;

use base58::{ToBase58, FromBase58};
use sha2::{Sha256, Digest, 
    digest::generic_array::GenericArray
};
use ripemd160::{Ripemd160};
use bincode;
use serde::{Serialize, Deserialize};
use flurry::HashMap;

#[derive(Serialize, Deserialize, Debug)]
enum GhostmatesMessage {
    Identify {
        ghostmates_address: String,
        pubkey: SodiumPublicKey,
    },
    SuccesfulIdentify,
    FailedIdentify,
    SuccesfulLookup {
        pubkey: SodiumPublicKey,
        ghostmates_address: String,
    },
    FailedLookup {
        ghostmates_address: String,
    },
    Lookup {
        dest_address: String,
    },
    DirectMessage {
        dest_address: String,
        encrypted_message: Vec<u8>,
        nonce: SodiumNonce
    },
    IncomingMessage {
        from_address: String,
        encrypted_message: Vec<u8>,
        nonce: SodiumNonce
    },
}

async fn handle_connection(raw_stream: TcpStream, addr: SocketAddr, peer_map: Arc<HashMap<String, IPKeyRow>>) -> Result<(), IoError> {

    println!("got a connection!");

    let ws_stream = match async_tungstenite::accept_async(raw_stream).await {
        Ok(w) => w,
        Err(_e) => {
            return Err(IoError::new(ErrorKind::Other, "Error accepting ws stream"))
        }
    };

    println!("WebSocket connection established: {}", addr);

    let (mut tx, rx) = unbounded();
    let arc_tx = Arc::new(Mutex::new(tx));
    let (outgoing, incoming) = ws_stream.split();
    let mut ghost_address_of_user : Option<String> = None;

    let broadcast_incoming = incoming.
    try_filter(|msg| {
        future::ready(!msg.is_close())
    })
    .try_for_each(|msg| {
        if let Message::Binary(d) = msg {
            let gm : GhostmatesMessage = match bincode::deserialize(&d) {
                Ok(g) => g,
                Err(e) => {
                    return future::ready(Err(TungsteniteError::Io(
                        IoError::new(ErrorKind::Other, "Not a Ghostmates-formatted Message")
                    )))
                }
            };
            println!("The addr: {:?}", addr);
            route(&gm, arc_tx.clone(), peer_map.clone(), addr.clone(), &mut ghost_address_of_user)
        }
        else {
            future::ready(Err(TungsteniteError::Io(
                IoError::new(ErrorKind::Other, "Not a Binary message!")
            )))
        }
    });

    let receive_from_others = rx.map(Ok).forward(outgoing);
    pin_mut!(broadcast_incoming, receive_from_others);

    future::select(broadcast_incoming, receive_from_others).await;
    println!("{:?} disconnected", addr);
    println!("{:?}", peer_map);
    if let Some(gaddr) = ghost_address_of_user {
        peer_map.remove(&gaddr, &peer_map.guard());
        println!("{:?}", peer_map);
    }
    else {
        println!("The user {:?} was not logged in.", addr);
    }
    Ok(())

}

fn route(gm: &GhostmatesMessage, tx: Arc<Mutex<UnboundedSender<Message>>>, peer_map: Arc<HashMap<String, IPKeyRow>>, addr: SocketAddr, ghost_address_of_user: &mut Option<String>) -> futures::future::Ready<Result<(), TungsteniteError>> {
    println!("ROUTING");
    println!("{:?}", gm);
    match gm {
        GhostmatesMessage::Identify {
            ghostmates_address,
            pubkey,
        } => {
            let addr_from_pk = address_from_sodium_pk(&pubkey);
            let id_response : GhostmatesMessage = if addr_from_pk.eq(&ghostmates_address.clone()) {
                *ghost_address_of_user = Some(ghostmates_address.to_owned());
                let row = IPKeyRow {
                    tx: tx.clone(),
                    pkey: pubkey.clone()
                };
                if peer_map.contains_key(&ghostmates_address.to_string(), &peer_map.guard()) {
                    println!("he's already logged in...");
                }
                else {
                    println!("Not in the table yet.");
                    peer_map.insert(ghostmates_address.to_string(), row, &peer_map.guard());
                }
                GhostmatesMessage::SuccesfulIdentify
            }
            else {
                GhostmatesMessage::FailedIdentify
            };
            let serialized : Vec<u8> = match bincode::serialize(&id_response){
                Ok(v) => v,
                Err(e) => {
                    return future::ready(Err(TungsteniteError::Io(
                        IoError::new(ErrorKind::Other, "Not a Binary message!")
                    )))
                }
            };
            task::block_on(
                tx
                .lock()
                .unwrap()
                .send(
                    Message::Binary(serialized)
                )
            );
            future::ready(Ok(()))
        },
        GhostmatesMessage::Lookup {
            dest_address,
        } => {
            println!("It's a lookup for {}", dest_address);
            let lookup_response = match peer_map.get(dest_address, &peer_map.guard()) {
                Some(row) => GhostmatesMessage::SuccesfulLookup {
                    pubkey: row.pkey,
                    ghostmates_address: dest_address.to_string(),
                },
                None => GhostmatesMessage::FailedLookup { ghostmates_address: dest_address.to_string() }
            };
            let serialized : Vec<u8> = match bincode::serialize(&lookup_response){
                Ok(v) => v,
                Err(e) => {
                    return future::ready(Err(TungsteniteError::Io(
                        IoError::new(ErrorKind::Other, "Not a Binary message!")
                    )))
                }
            };
            task::block_on(
                tx
                .lock()
                .unwrap()
                .send(
                    Message::Binary(serialized)
                )
            );
            future::ready(Ok(()))
        },
        GhostmatesMessage::DirectMessage {
            dest_address,
            encrypted_message,
            nonce,
        } => {
            if let Some(row) = peer_map.get(dest_address, &peer_map.guard()) {
                if let Some(from) = ghost_address_of_user {
                    let outgoing = GhostmatesMessage::IncomingMessage {
                        from_address : from.to_string(),
                        encrypted_message : encrypted_message.to_vec(),
                        nonce: nonce.clone(),
                    };
                    let serialized = bincode::serialize(&outgoing)
                        .expect("Could not serialize");
                    task::block_on(
                        row.tx
                            .lock().unwrap()
                            .send(
                                Message::Binary(serialized)
                            )
                    );
                    return future::ready(Ok(()))
                }
            }
            return future::ready(Err(TungsteniteError::Io(
                IoError::new(ErrorKind::Other, "No code for this message_type yet")
            )))
        },
        _ => {
            println!("It's in the other kind");
            return future::ready(Err(TungsteniteError::Io(
                IoError::new(ErrorKind::Other, "No code for this message_type yet")
            )))
        }
    }
}

async fn websocket_loop(peer_map: Arc<HashMap<String, IPKeyRow>>) {

    let addr = "127.0.0.1:4000".to_string();
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind.");
    println!("Listening on {}", addr);

    while let Ok((stream, addr)) = listener.accept().await {
        task::spawn(handle_connection(stream, addr, peer_map.clone()));
    }
}

pub fn address_from_sodium_pk(pk: &SodiumPublicKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pk.as_ref());
    let result = hasher.finalize();
    let sha256hash : Vec<u8> = result.as_slice().to_owned();
    let mut ripemd_hasher = Ripemd160::new();
    ripemd_hasher.update(sha256hash);
    let ripemd_result = ripemd_hasher.finalize();
    let ripemdhash: Vec<u8> = ripemd_result.as_slice().to_owned(); 
    let mut base58 = ripemdhash.to_base58();
    base58.push_str(".ghost");
    base58
}

#[derive(Debug)]
struct IPKeyRow {
    tx: Arc<Mutex<UnboundedSender<Message>>>,
    pkey: SodiumPublicKey,
}

fn main() {
    let peer_map = Arc::new(HashMap::<String, IPKeyRow>::new());
    task::block_on(websocket_loop(peer_map.clone()));
}
