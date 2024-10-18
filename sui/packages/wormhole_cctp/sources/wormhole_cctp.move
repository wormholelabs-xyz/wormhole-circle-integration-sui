/// This library enables an integration pattern where a program sends a CCTP
/// transfer (via Circle's `token_messenger_minter` package) along with some
/// additional payload (via Wormhole), to be consumed together.
///
/// The Sui implementation deviates from the EVM/Solana implementations in
/// several ways, due to limitations in the CCTP library Sui implementation.
///
/// First we review how the Solana/EVM implementations work, then discuss the
/// differences here.
///
/// # Solana/EVM
///
/// When sending a CCTP+payload transfer, the integrator contract (atomically)
/// calls `deposit_for_burn_with_caller` (Solana) or `depositForBurnWithCaller`
/// (EVM) on the CCTP contract, and `publish_message` on the Wormhole contract.
/// The CCTP contract call will burn the tokens and send a CCTP transfer to the
/// specified destination chain, which encodes information such as the mint
/// recipient, token address, amount, and the source chain, and CCTP nonce.
/// The wormhole message encodes this same information, and
/// includes an additional dynamic length byte array, which is to be consumed by
/// the integrator's destination chain contract.
/// The result of this call is a pair of: a CCTP attestation, and a Wormhole VAA.
///
/// CCTP exposes a `deposit_for_burn` and a `deposit_for_burn_with_caller`
/// function, with the latter restricting who can perform the minting action on
/// the destination chain. The Wormhole CCTP library sets this destination
/// caller as the destination chain integrator contract (typically maintained
/// through some cross-chain registry). This effectively guarantees that the
/// destination contract is always made aware of the transfer, together with the
/// accompanying payload.
///
/// Completing the flow, on the receiving side, the integrator contract takes
/// teh CCTP attestation and the Wormhole VAA, and atomically redeems the CCTP
/// transfer, and acts on the payload in the VAA after verifying it. Beyond
/// verifying the signatures and the (registered) sender contract, it also
/// ensures that the VAA actually belongs to the CCTP transfer. A CCTP transfer
/// is uniquely identified by the pair of (source domain, cctp nonce). This
/// means that if the source chain and the nonce fields encoded in the VAA match
/// those in the CCTP message, then they came from the same contract.
/// Because these two are always atomically redeemed together, the library does
/// not separately replay protect the VAA redemption, as the entire process
/// inherits replay protection from that of the CCTP transfer.
///
/// # Sui
///
/// In the EVM and Solana implementations of the token messenger minter
/// contracts, the `deposit_for_burn_with_caller` function (or rather, its
/// handling in `receive_message`) allows restricting the minting action to a
/// contract. On EVM, this is done by checking for msg.sender and on Solana by
/// checking for a signer (which itself can be a PDA).
///
/// The Sui implementation deviates from this by only allowing an EOA
/// to trigger minting, but not a contract, because the destination caller check
/// is done via `ctx.sender()` which is roughly equivalent to `tx.origin` in EVM.
///
/// This effectively means that integrators who want to perform some action on
/// CCTP token transfers can not rely on their contract being able to redeem the
/// transfer (unless they run some permissioned EOA that triggers contract
/// execution, which is not an option for our library).
///
/// Instead, we alter the EVM/Solana flow in the following way:
/// When sending a transfer to Sui, the regular `deposit_for_burn` action is
/// used, instead of `deposit_for_burn_with_caller`.
/// This means that anyone can redeem the transfer on Sui, and in particular a
/// malicious actor can frontrun us and trigger minting before the integrator
/// contract would get to do it. To avoid this issue, we separate CCTP
/// redemption from the VAA redemption.
///
/// In our library, we are only concerned with the VAA redeem step, and simply
/// require the client to have redeemed the CCTP transfer. The client may do
/// both of them atomically (via a programmable transaction block), but in that
/// case they need to ensure that the transfer is not already redeemed.
///
/// The VAA handling code simply verifies the VAA, and checks that the
/// corresponding CCTP transfer (identified by the (source chain, cctp nonce)
/// pair that's encoded in the VAA) is already redeemed by invoking the
/// `is_nonce_used` function from the CCTP package. If it is, it means that
/// the VAA in question corresponds to a valid CCTP transfer that was intended
/// for this chain. That's because the CCTP library itself checks that Sui is
/// the correct destination for the transfer.
/// Since the VAA, contains all the transfer information anyway (such as amount
/// and recipient), checking that the transfer is redeemed is sufficient, and we
/// don't need access to the original CCTP message.
///
/// Note: we could take the CCTP attestation here, and verify each field against
/// the VAA fields. That would protect against certain types of attacks, such as
/// if the sending chain can send VAAs with different information (like amount)
/// than what was encoded in the transfer. The Solana implementation trusts the
/// VAA, so we do it too. Verifying the CCTP attestation separately would incur
/// significant code complexity overhead, as we would have to copy paste the
/// entire attestation verification code from the CCTP library, as the relevant
/// functions are private.
///
/// Decoupling the VAA verification from CCTP redeem action means that replay
/// protection is no longer inherited in the VAA component from the CCTP
/// component like it was on EVM/Solana. Thus, separate explicit replay
/// protection is performed by our library.
///
/// ## Upgrade safety
///
/// Throughout the library, we classify each public function whether it's
/// upgrade safe or not. If a function is upgrade safe, it means it's designed
/// to be called directly from an integrator contract (and specifically that
/// upgrading this library or the CCTP library) will not break the integrator.
/// If a function is not upgrade safe, it is intended to be called in a
/// programmable transaction block.
///
/// In our library, every non-upgrade safe function is explicitly designed to be
/// safely callable from a PTB. This is a conscious design choice, and it
/// enables integrators to safely use the library without risk of breaking on
/// upgrades. The only reason this library needs to be upgradeable is because
/// Circle's CCTP library is not designed in this way (some non-upgrade safe
/// functions cannot be safely called from PTBs), so we need to wrap
/// functionality in PTB-safe wrappers. See the
/// `wormhole_cctp::deposit_for_burn` module for more.
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

    /// NOTE: upgrade safe
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
                burn_message.amount() as u256,
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


    /// NOTE: upgrade safe
    /// NOTE: it's the caller's responsibility to check that the (source_chain, source_address) is trusted.
    /// TODO: add example integration contract
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
module wormhole_cctp::wormhole_cctp_tests {
    use sui::{
        coin,
        deny_list::{Self, DenyList},
        test_scenario::{Self, Scenario},
        test_utils,
    };
    use stablecoin::treasury::{Self, Treasury, MintCap};
    use token_messenger_minter::{
        remote_token_messenger,
        token_controller,
        burn_message,
        handle_receive_message,
        message_transmitter_authenticator::MessageTransmitterAuthenticator,
        state as token_messenger_state,
    };
    use message_transmitter::{
        receive_message::{Self, complete_receive_message},
        send_message::auth_caller_identifier,
        state as message_transmitter_state,
    };

    public struct WORMHOLE_CCTP_TESTS has drop {}

    const USER: address = @0x1A;
    const ADMIN: address = @0x2B;
    const LOCAL_DOMAIN: u32 = 0;
    const REMOTE_DOMAIN: u32 = 1;
    const REMOTE_TOKEN_MESSENGER: address = @0x0000000000000000000000003b61AbEe91852714E4e99b09a1AF3e9C13893eF1;
    const REMOTE_TOKEN: address = @0x0000000000000000000000001c7D4B196Cb0C7B01d743Fbc6116a902379C7238;
    // const MINT_RECIPIENT: address = @0x1f26414439c8d03fc4b9ca912cefd5cb508c9605;
    const AMOUNT: u64 = 1214;
    const VERSION: u32 = 0;

    #[test]
    public fun test_handle_receive_message_successful() {
        let mut scenario = test_scenario::begin(ADMIN);
        let (mint_cap, mut treasury, deny_list) = setup_coin(&mut scenario);
        let (mut token_messenger_state, message_transmitter_state) = setup_cctp_states(
            mint_cap, &mut scenario
        );

        scenario.next_tx(USER);
        {
            // Get a fake receipt. In real scenarios this would be returned from receive_message.
            let receipt = receive_message::create_receipt(
                USER,
                auth_caller_identifier<MessageTransmitterAuthenticator>(),
                REMOTE_DOMAIN,
                REMOTE_TOKEN_MESSENGER,
                12,
                burn_message::get_raw_test_message(),
                1
            );

            let stamped_receipt = handle_receive_message::handle_receive_message(
                receipt,
                &mut token_messenger_state,
                &message_transmitter_state,
                &deny_list,
                &mut treasury,
                scenario.ctx()
            );

            complete_receive_message(stamped_receipt, &message_transmitter_state);

            // TODO: currently it's not possible to mock a VAA. add a
            // [test_only] method to the wormhole sui package to do that.
            // wormhole_cctp::consume_payload()
        };

        test_utils::destroy(token_messenger_state);
        test_utils::destroy(message_transmitter_state);
        test_utils::destroy(deny_list);
        test_utils::destroy(treasury);
        scenario.end();
    }

    // TODO: test replay protection
    // TODO: test that we can't redeem a VAA if the CCTP message is not redeemed

    // === Test-Functions ===

    fun setup_coin<T: drop>(
        scenario: &mut Scenario
    ): (MintCap<T>, Treasury<T>, DenyList) {
        let otw = test_utils::create_one_time_witness<T>();
        let (treasury_cap, deny_cap, metadata) = coin::create_regulated_currency_v2(
            otw,
            6,
            b"SYMBOL",
            b"NAME",
            b"",
            option::none(),
            true,
            scenario.ctx()
        );

        let mut treasury = treasury::new(
            treasury_cap,
            deny_cap,
            scenario.ctx().sender(),
            scenario.ctx().sender(),
            scenario.ctx().sender(),
            scenario.ctx().sender(),
            scenario.ctx().sender(),
            scenario.ctx()
        );
        treasury.configure_new_controller(ADMIN, ADMIN, scenario.ctx());
        scenario.next_tx(ADMIN);
        let mint_cap = scenario.take_from_address<MintCap<T>>(ADMIN);
        let deny_list = deny_list::new_for_testing(scenario.ctx());
        treasury.configure_minter(&deny_list, 999999999, scenario.ctx());
        test_utils::destroy(metadata);


        // Mint some coins for the user
        treasury::mint(
            &mut treasury, &mint_cap, &deny_list, AMOUNT as u64, USER, scenario.ctx()
        );

        (mint_cap, treasury, deny_list)
    }

    fun setup_cctp_states(
        mint_cap: MintCap<WORMHOLE_CCTP_TESTS>,
        scenario: &mut Scenario
    ): (token_messenger_state::State, message_transmitter_state::State) {
        let ctx = test_scenario::ctx(scenario);

        let mut token_messenger_state = token_messenger_state::new_for_testing(VERSION, ADMIN, ctx);
        let message_transmitter_state = message_transmitter_state::new_for_testing(
            LOCAL_DOMAIN, VERSION, 1000, ADMIN, ctx
        );

        remote_token_messenger::add_remote_token_messenger(
            REMOTE_DOMAIN, REMOTE_TOKEN_MESSENGER, &mut token_messenger_state, ctx
        );

        token_controller::add_stablecoin_mint_cap(
            mint_cap, &mut token_messenger_state, ctx
        );

        token_controller::link_token_pair<WORMHOLE_CCTP_TESTS>(
            REMOTE_DOMAIN, REMOTE_TOKEN, &mut token_messenger_state, ctx
        );

        token_controller::set_max_burn_amount_per_message<WORMHOLE_CCTP_TESTS>(
            1000000, &mut token_messenger_state, ctx
        );

        (token_messenger_state, message_transmitter_state)
    }
}
