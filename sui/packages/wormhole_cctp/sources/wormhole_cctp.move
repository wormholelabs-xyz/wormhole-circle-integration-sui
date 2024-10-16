module wormhole_cctp::wormhole_cctp {
    use message_transmitter::state::{State as CctpState};
    use wormhole::emitter::EmitterCap;
    use wormhole::external_address::{Self, ExternalAddress};
    use wormhole::publish_message::{Self, MessageTicket};
    use wormhole::vaa::VAA;
    use wormhole::consumed_vaas::ConsumedVAAs;
    use wormhole_cctp::deposit::{Self, Deposit};
    use wormhole_cctp::payload;

    use wormhole_cctp::deposit_for_burn::BurnWitness;

    // NOTE: upgrade safe
    public fun publish(
        emitter_cap: &mut EmitterCap,
        wormhole_nonce: u32,
        payload: vector<u8>,
        // TODO: we could just take a reference to this and mark it as sent somehow
        // internally. more complexity, but it does allow for multiple uses of the
        // witness. that would be the right solution if this was upstreamed.
        burn_witness: BurnWitness,
    ): MessageTicket {
        let (burn_message, message) = burn_witness.destruct();

        publish_message::prepare_message(
            emitter_cap,
            wormhole_nonce,
            payload::new_deposit(deposit::new(
                external_address::from_address(burn_message.burn_token()),
                burn_message.amount() as u256, // NOTE: this is guaranteed to be equal to the amount
                message.source_domain(),
                message.destination_domain(),
                message.nonce(),
                external_address::from_address(burn_message.message_sender()), // TODO: this is just ctx sender. is that good enough for us?
                external_address::from_address(burn_message.mint_recipient()),
                payload
            )).serialize()
        )
    }

    #[error]
    const ENonceNotClaimedYet: vector<u8> =
            b"The nonce has not been claimed yet.";

    // TODO: document
    /// NOTE: upgrade safe
    /// NOTE: it's the caller's responsibility to check that the (source_chain,
    ///             source_address) is trusted. TODO: example
    public fun consume_payload(
        vaa: VAA,
        cctp_state: &mut CctpState,
        consumed_vaas: &mut ConsumedVAAs,
    ): (u16, ExternalAddress, Deposit) {
        consumed_vaas.consume(vaa.digest());

        let (source_chain, source_address, payload) = vaa.take_emitter_info_and_payload();

        let deposit = payload::parse(payload).deposit();

        let cctp_claimed = cctp_state.is_nonce_used(deposit.source_cctp_domain(), deposit.cctp_nonce());
        assert!(cctp_claimed, ENonceNotClaimedYet);

        (source_chain, source_address, deposit)
    }
}


#[test_only]
module wormhole_cctp::test {

}
