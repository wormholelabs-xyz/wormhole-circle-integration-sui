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

#[test_only]
module wormhole_cctp::deposit_tests {
    use wormhole_cctp::deposit;
    use wormhole::external_address;

    #[test]
    fun test_deposit_serialization_deserialization() {
        // Create mock data
        let token_address = external_address::from_address(@010101);
        let amount = 1342523u256;
        let source_cctp_domain = 1u32;
        let destination_cctp_domain = 2u32;
        let cctp_nonce = 12345u64;
        let burn_source = external_address::from_address(@020202);
        let mint_recipient = external_address::from_address(@030303);
        let payload = b"Test payload";

        // Create a Deposit struct
        let deposit = deposit::new(
            token_address,
            amount,
            source_cctp_domain,
            destination_cctp_domain,
            cctp_nonce,
            burn_source,
            mint_recipient,
            payload
        );

        // Serialize the deposit
        let serialized = deposit::serialize(deposit);

        // Deserialize the deposit
        let deserialized = deposit::parse(serialized);

        // Assert equality for all fields
        assert!(deposit::token_address(&deserialized) == token_address, 0);
        assert!(deposit::amount(&deserialized) == amount, 1);
        assert!(deposit::source_cctp_domain(&deserialized) == source_cctp_domain, 2);
        assert!(deposit::destination_cctp_domain(&deserialized) == destination_cctp_domain, 3);
        assert!(deposit::cctp_nonce(&deserialized) == cctp_nonce, 4);
        assert!(deposit::burn_source(&deserialized) == burn_source, 5);
        assert!(deposit::mint_recipient(&deserialized) == mint_recipient, 6);
        assert!(deposit::payload(&deserialized) == payload, 7);
    }
}
