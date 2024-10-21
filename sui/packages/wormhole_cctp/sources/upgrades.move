/// The upgradeability story.
/// This library is intended to be immutable. The only reason it needs to be
/// upgradeable is because it wraps the CCTP library, which itself is
/// upgradeable (see the `deposit_for_burn` module for details).
///
/// Thus the only reason this library would be upgraded is to upgrade the
/// underlying CCTP library version.
///
/// Sui supports restricting the upgrade policy of a package to
/// "dependency-only", meaning that only the dependencies can be upgraded, but
/// the existing contract code in the package itself cannot be modified.
///
/// In order to avoid the complexity (and operational overhead) of setting up
/// Guardian governance for this library, we instead allow *anyone* to upgrade
/// the package, but only the dependencies.
///
/// To do this, on initial deployment, the deployer must call the
/// `init_upgrade_policy` function which takes the upgrade capability, restricts
/// it to only dependency upgrades, and wraps it in `DependencyUpgradeCap`,
/// which is then turned into a shared object.
///
/// This way, anyone can later call `authorize_upgrade` with this shared object,
/// authorising an ugprade that updates the dependencies.
///
/// The following properties are required for the safety of this module:
/// - [ VERIFIED ] sui indeed doesn't allow non-dependency upgrades in such mode
/// - [ VERIFIED ] sui doesn't allow swapping out the dependency for another
///                 one, only other versions of the same package
///
/// Unfortunately, sui allows downgrading dependencies (as long as the
/// downgraded version is at least as new as the original dependency that the
/// package was originally published against).
/// This poses a challenge to our permissionless upgrade scheme, because a
/// malicious actor could simply downgrade the cctp dependencies, breaking the
/// library.
/// To protect against this, we require invoking the `check_dep_versions`
/// function after committing an upgrade, which will ensure that the new version
/// links against no older versions than the previous version. The linked
/// versions are stored in the `DependencyUpgradeCap` state.
///
/// TODO: can transitive dep versions be manipulated?
module wormhole_cctp::upgrades {
    use sui::package::UpgradeCap;

    public struct DependencyUpgradeCap has key, store {
        id: UID,
        upgrade_cap: UpgradeCap,
        message_transmitter_version: u64,
        token_messenger_minter_version: u64,
        stablecoin_version: u64,
    }

    public fun init_upgrade_policy(mut upgrade_cap: UpgradeCap, ctx: &mut TxContext) {
        sui::package::only_dep_upgrades(&mut upgrade_cap);

        // make sure that the upgrade cap is for this package, and that it's on
        // version 1 (i.e. no upgrades have been performed yet).
        wormhole::package_utils::assert_package_upgrade_cap<DependencyUpgradeCap>(
            &upgrade_cap,
            sui::package::dep_only_policy(),
            1
        );

        transfer::public_share_object(
            DependencyUpgradeCap {
                id: object::new(ctx),
                upgrade_cap,
                message_transmitter_version: message_transmitter::version_control::current_version(),
                token_messenger_minter_version: token_messenger_minter::version_control::current_version(),
                stablecoin_version: stablecoin::version_control::current_version(),
            }
        );
    }

    public fun authorize_upgrade(
        cap: &mut DependencyUpgradeCap,
        policy: u8,
        digest: vector<u8>,
    ): sui::package::UpgradeTicket {
        sui::package::authorize_upgrade(&mut cap.upgrade_cap, policy, digest)
    }

    /// This struct ensures that `check_dep_versions` is invoked after `commit_upgrade`.
    public struct CheckDepVersions {}

    public fun commit_upgrade(
        cap: &mut DependencyUpgradeCap,
        receipt: sui::package::UpgradeReceipt,
    ): CheckDepVersions {
        sui::package::commit_upgrade(&mut cap.upgrade_cap, receipt);
        CheckDepVersions {}
    }

    /// This is called after `commit_upgrade`.
    /// NOTE: it's not possible to guarantee that this is invoked from the
    /// latest version of the package directly (sui doesn't expose a mechanism
    /// to do that).
    /// However, the version checks here do ensure that.
    /// The assumption is that the underlying CCTP libraries are versioned
    /// properly, i.e. their version is bumped on each upgrade.
    /// If they perform upgrades without bumping the version, then we have no
    /// way of checking if we're linking against the most recent version, and in
    /// that case downgrades would be possible.
    public fun check_dep_versions(cap: &mut DependencyUpgradeCap, sync: CheckDepVersions) {
        let CheckDepVersions {} = sync;

        let message_transmitter_linked_version = message_transmitter::version_control::current_version();
        let token_messenger_minter_linked_version = token_messenger_minter::version_control::current_version();
        let stablecoin_linked_version = stablecoin::version_control::current_version();

        assert!(cap.message_transmitter_version <= message_transmitter_linked_version);
        assert!(cap.token_messenger_minter_version <= token_messenger_minter_linked_version);
        assert!(cap.stablecoin_version <= stablecoin_linked_version);

        cap.message_transmitter_version = message_transmitter_linked_version;
        cap.token_messenger_minter_version = token_messenger_minter_linked_version;
        cap.stablecoin_version = stablecoin_linked_version;
    }

}
