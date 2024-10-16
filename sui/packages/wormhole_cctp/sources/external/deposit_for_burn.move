/// This module wraps the [`token_messenger_minter::deposit_for_burn`] functions
/// (`deposit_for_burn` and `deposit_for_burn_with_caller`) in a way that makes
/// it safe to call them from PTBs, which in turn makes it possible to integrate
/// with the library in an upgrade-safe manner.
///
/// Why?
///
/// The original `deposit_for_burn` and `deposit_for_burn_with_caller` functions
/// are version gated, meaning that they will only work when invoked from the
/// most recent version of the `token_messenger_minter` package. Contracts that
/// directly call these functions will break when `token_messenger_minter` is
/// upgraded (as they will still hold a reference to the older version).
///
/// To avoid breaking, an integration pattern is to never call these functions
/// directly from a contract, but instead call them from a programmable
/// transaction block (PTB), followed by a call to the relevant contract call.
/// The PTB might look something like this:
///
/// ```
/// let result = token_messenger_minter::deposit_for_burn::deposit_for_burn(...args...);
/// my_contract::my_function(result);
/// ```
///
/// This way, when `token_messenger_minter` is upgraded, only a client side
/// change is necessary to use the most recent version.
/// However, as the `token_messenge_minter` package is designed, this pattern is
/// unsafe. This is because `result` is of type `(BurnMessage, Message)` where
/// both `BurnMessage` and `Message` have public constructors, so
/// `my_contract::my_function` has no guarantee that it's called with the result
/// of a `deposit_for_burn`. Instead, an attacker could just construct that
/// tuple directly without actually burning tokens, and invoke `my_function`.
/// Note that this is a direct consequence of the inversion of control flow that
/// the PTB introduced. When `my_function` calls `deposit_for_burn` directly, it
/// can be sure that the tokens are burnt.
///
/// How?
///
/// To solve the problem above, we need to ensure that
/// `my_contract::my_function` can verify that it's consuming the result of an
/// actual `deposit_for_burn` call.
/// It's simple to do this: just ensure that `deposit_for_burn` returns a value
/// that cannot be externally constructed, only by that function alone.
/// Move structs (with not public constructor functions) can only be constructed
/// by the module that defines them, so we simply wrap the `BurnMessage` and
/// `Message` in such a struct, instead of a tuple. We call this struct
/// `BurnWitness`, because it witnesses the fact that a burn was done.
///
/// Now the same pattern (note that we're invoking the wrapper instead of the
/// original from `token_messenger_minter`) is safe
///
/// ```
/// let result = wormhole_cctp::deposit_for_burn::deposit_for_burn(...args...);
/// my_contract::my_function(result);
/// ```
///
/// because `result` is of type `BurnWitness`.
///
/// We expose a public destructor (`destruct`), but no public constructor.
module wormhole_cctp::deposit_for_burn {
    use message_transmitter::state::{State as CctpState};
    use message_transmitter::message::Message;
    use stablecoin::treasury::Treasury;
    use sui::coin::Coin;
    use sui::deny_list::DenyList;
    use token_messenger_minter::state::{State as TokenMessengerMinterState};
    use token_messenger_minter::burn_message::BurnMessage;
    use wormhole::external_address::ExternalAddress;

    public struct BurnWitness has drop {
        burn_message: BurnMessage,
        message: Message
    }

    public fun destruct(burn_witness: BurnWitness): (BurnMessage, Message) {
        let BurnWitness { burn_message, message } = burn_witness;
        (burn_message, message)
    }

    // TODO: make this package upgradeable. The only reason it should ever be
    // upgraded is to upgrade the underlying deposit_for_burn_with_caller function.
    // TODO: introduce a function that checks that the appropriate version was
    // called for the destination chain (i.e. for a sui target we don't want the
    // _with_caller version).

    /// NOTE: not upgrade safe! call this from a PTB.
    public fun deposit_for_burn_with_caller<T: drop>(
        coin: Coin<T>,
        cctp_state: &mut CctpState,
        token_messenger_minter_state: &mut TokenMessengerMinterState,
        cctp_destination_domain: u32,
        mint_recipient: ExternalAddress,
        destination_caller: ExternalAddress,
        deny_list: &DenyList,
        treasury: &mut Treasury<T>,
        ctx: &TxContext
    ): BurnWitness {
        use token_messenger_minter::deposit_for_burn::{deposit_for_burn_with_caller as impl};

        let (burn_message, message) = impl(
            coin,
            cctp_destination_domain,
            mint_recipient.to_address(),
            destination_caller.to_address(),
            token_messenger_minter_state,
            cctp_state,
            deny_list,
            treasury,
            ctx
        );
        BurnWitness { burn_message, message }
    }

    /// NOTE: not upgrade safe! call this from a PTB.
    public fun deposit_for_burn<T: drop>(
        coin: Coin<T>,
        cctp_state: &mut CctpState,
        token_messenger_minter_state: &mut TokenMessengerMinterState,
        cctp_destination_domain: u32,
        mint_recipient: ExternalAddress,
        deny_list: &DenyList,
        treasury: &mut Treasury<T>,
        ctx: &TxContext
    ): BurnWitness {
        use token_messenger_minter::deposit_for_burn::{deposit_for_burn as impl};

        let (burn_message, message) = impl(
            coin,
            cctp_destination_domain,
            mint_recipient.to_address(),
            token_messenger_minter_state,
            cctp_state,
            deny_list,
            treasury,
            ctx
        );
        BurnWitness { burn_message, message }
    }
}
