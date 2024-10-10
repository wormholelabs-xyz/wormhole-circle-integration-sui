module wormhole_cctp::wormhole_cctp {
  use message_transmitter::receive_message::{Receipt, StampedReceipt};
  use message_transmitter::state::{State as CctpState};
  use stablecoin::treasury::Treasury;
  use sui::coin::Coin;
  use sui::deny_list::DenyList;
  use token_messenger_minter::deposit_for_burn::deposit_for_burn_with_caller;
  use token_messenger_minter::handle_receive_message::handle_receive_message;
  use token_messenger_minter::state::{State as TokenMessengerMinterState};
  use wormhole::emitter::EmitterCap;
  use wormhole::external_address::{Self, ExternalAddress};
  use wormhole::publish_message::{Self, MessageTicket};
  use wormhole::vaa::VAA;
  use wormhole_cctp::deposit;
  use wormhole_cctp::payload;

  public fun burn_and_publish<T: drop>(
    coin: Coin<T>,
    emitter_cap: &mut EmitterCap,
    cctp_state: &mut CctpState,
    token_messenger_minter_state: &mut TokenMessengerMinterState,
    cctp_destination_domain: u32,
    mint_recipient: ExternalAddress,
    destination_caller: ExternalAddress,
    deny_list: &DenyList,
    treasury: &mut Treasury<T>,
    wormhole_nonce: u32,
    payload: vector<u8>,
    ctx: &TxContext
  ): MessageTicket {
    let mint_recipient_address: address = mint_recipient.to_address();

    let (burn_message, message) = deposit_for_burn_with_caller(
      coin,
      cctp_destination_domain,
      mint_recipient_address,
      destination_caller.to_address(),
      token_messenger_minter_state,
      cctp_state,
      deny_list,
      treasury,
      ctx
    );

    publish_message::prepare_message(
      emitter_cap,
      wormhole_nonce,
      payload::new_deposit(deposit::new(
        external_address::from_address(burn_message.burn_token()),
        burn_message.amount() as u256, // NOTE: this is guaranteed to be equal to the amount
        message.source_domain(),
        cctp_destination_domain,
        message.nonce(),
        external_address::from_address(burn_message.message_sender()), // TODO: this is just ctx sender. is that good enough for us?
        external_address::from_address(burn_message.mint_recipient()),
        payload
      )).serialize()
    )
  }

  #[error]
  const ESourceCctpDomainMismatch: vector<u8> =
      b"Unexpected CCTP source domain.";

  #[error]
  const EDestinationCctpDomainMismatch: vector<u8> =
      b"Unexpected CCTP destination domain.";

  #[error]
  const ECctpNonceMismatch: vector<u8> =
      b"Unexpected CCTP nonce.";

  public fun mint<T: drop>(
    vaa: VAA,
    receipt: Receipt,
    cctp_state: &mut CctpState,
    token_messenger_minter_state: &mut TokenMessengerMinterState,
    deny_list: &DenyList,
    treasury: &mut Treasury<T>,
    ctx: &mut TxContext
  ): StampedReceipt {
    let (source_chain, source_address, payload) = vaa.take_emitter_info_and_payload();

    let deposit = payload::parse(payload).deposit();

    assert!(deposit.source_cctp_domain() == receipt.source_domain(), ESourceCctpDomainMismatch);
    assert!(deposit.destination_cctp_domain() == cctp_state.local_domain(), EDestinationCctpDomainMismatch);
    // assert!(deposit.cctp_nonce() == receipt.nonce(), ECctpNonceMismatch); TODO: .nonce() is not exposed for receipt

    handle_receive_message(
      receipt,
      token_messenger_minter_state,
      cctp_state,
      deny_list,
      treasury,
      ctx
    )
  }
}

module wormhole_cctp::payload {
  use wormhole::bytes;
  use wormhole::cursor;
  use wormhole_cctp::deposit::{Self, Deposit};

  #[error]
  const EInvalidPayload: vector<u8> =
      b"Invalid payload type.";

  public enum Payload {
    Deposit(Deposit),
  }

  public fun new_deposit(d: Deposit): Payload {
    Payload::Deposit(d)
  }

  public fun deposit(payload: Payload): Deposit {
    match (payload) {
      Payload::Deposit(d) => d,
      // _ => abort(EUnexpectedVariant)
    }
  }

  public fun serialize(payload: Payload): vector<u8> {
    let mut buf = vector::empty<u8>();
    match (payload) {
      Payload::Deposit(d) => {
        bytes::push_u8(&mut buf, 1);
        buf.append(d.serialize());
      }
    };
    buf
  }

  public fun parse(buf: vector<u8>): Payload {
    let mut cur = cursor::new(buf);
    let payload_type = bytes::take_u8(&mut cur);
    let payload = match (payload_type) {
      1 => Payload::Deposit(deposit::take_bytes(&mut cur)),
      _ => abort(EInvalidPayload)
    };
    cur.destroy_empty();
    payload
  }
}

module wormhole_cctp::deposit {
  use wormhole::bytes;
  use wormhole::external_address::{ExternalAddress};
  use wormhole::cursor;
  use wormhole::external_address;

  public struct Deposit has drop {
    token_address: ExternalAddress,
    amount: u256,
    source_cctp_domain: u32,
    destination_cctp_domain: u32,
    cctp_nonce: u64,
    burn_source: ExternalAddress,
    mint_recipient: ExternalAddress,
    // NOTE: This payload length is encoded as u16.
    payload: vector<u8>
  }

  public fun token_address(deposit: &Deposit): ExternalAddress {
    deposit.token_address
  }

  public fun amount(deposit: &Deposit): u256 {
    deposit.amount
  }

  public fun source_cctp_domain(deposit: &Deposit): u32 {
    deposit.source_cctp_domain
  }

  public fun destination_cctp_domain(deposit: &Deposit): u32 {
    deposit.destination_cctp_domain
  }

  public fun cctp_nonce(deposit: &Deposit): u64 {
    deposit.cctp_nonce
  }

  public fun burn_source(deposit: &Deposit): ExternalAddress {
    deposit.burn_source
  }

  public fun mint_recipient(deposit: &Deposit): ExternalAddress {
    deposit.mint_recipient
  }

  public fun payload(deposit: &Deposit): vector<u8> {
    deposit.payload
  }

  public fun new(
    token_address: ExternalAddress,
    amount: u256,
    source_cctp_domain: u32,
    destination_cctp_domain: u32,
    cctp_nonce: u64,
    burn_source: ExternalAddress,
    mint_recipient: ExternalAddress,
    payload: vector<u8>
  ): Deposit {
    Deposit {
      token_address,
      amount,
      source_cctp_domain,
      destination_cctp_domain,
      cctp_nonce,
      burn_source,
      mint_recipient,
      payload
    }
  }

  public fun serialize(deposit: Deposit): vector<u8> {
    let Deposit {
      token_address,
      amount,
      source_cctp_domain,
      destination_cctp_domain,
      cctp_nonce,
      burn_source,
      mint_recipient,
      payload
    } = deposit;
    let mut buf = vector::empty<u8>();
    vector::append(&mut buf, token_address.to_bytes());
    bytes::push_u256_be(&mut buf, amount);
    bytes::push_u32_be(&mut buf, source_cctp_domain);
    bytes::push_u32_be(&mut buf, destination_cctp_domain);
    bytes::push_u64_be(&mut buf, cctp_nonce);
    vector::append(&mut buf, burn_source.to_bytes());
    vector::append(&mut buf, mint_recipient.to_bytes());
    bytes::push_u16_be(&mut buf, payload.length() as u16);
    vector::append(&mut buf, payload);
    buf
  }

  public fun take_bytes(cur: &mut cursor::Cursor<u8>): Deposit {
    let token_address = external_address::take_bytes(cur);
    let amount = bytes::take_u256_be(cur);
    let source_cctp_domain = bytes::take_u32_be(cur);
    let destination_cctp_domain = bytes::take_u32_be(cur);
    let cctp_nonce = bytes::take_u64_be(cur);
    let burn_source = external_address::take_bytes(cur);
    let mint_recipient = external_address::take_bytes(cur);
    let payload_length = bytes::take_u16_be(cur);
    let payload = bytes::take_bytes(cur, payload_length as u64);
    Deposit {
      token_address,
      amount,
      source_cctp_domain,
      destination_cctp_domain,
      cctp_nonce,
      burn_source,
      mint_recipient,
      payload
    }
  }

  public fun parse(buf: vector<u8>): Deposit {
    let mut cur = cursor::new(buf);
    let deposit = take_bytes(&mut cur);
    cur.destroy_empty();
    deposit
  }
}
