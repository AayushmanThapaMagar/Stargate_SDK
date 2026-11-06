#![no_std]

//! On-chain authorization integration for Stargate on Stellar Soroban.

use soroban_sdk::{
    Address, Env, Executable, contracterror, contractevent, contracttype, panic_with_error,
};

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum StargateError {
    AlreadyInitialized = 1000,
    InvalidConfiguration = 1001,
    NotInitialized = 1002,
    AuthorityChanged = 1003,
}

#[contracttype]
enum StorageKey {
    StargateConfig,
}

#[contracttype]
struct ConfigV1 {
    admin: Address,
    authority: Address,
}

#[contractevent]
struct StargateInitialized {
    admin: Address,
    authority: Address,
}

#[contractevent]
struct StargateAuthorityRotated {
    previous_authority: Address,
    new_authority: Address,
}

pub struct StargateGuard;

impl StargateGuard {
    /// Initializes Stargate configuration for the current contract.
    ///
    /// Call this from the consuming contract's `__constructor` or an
    /// independently authenticated migration.
    pub fn initialize(env: &Env, admin: &Address, authority: &Address) {
        let storage = env.storage().instance();
        let key = StorageKey::StargateConfig;

        if storage.has(&key) {
            panic_with_error!(env, StargateError::AlreadyInitialized);
        }

        if admin == authority
            || admin == &env.current_contract_address()
            || !matches!(authority.executable(), Some(Executable::Account))
        {
            panic_with_error!(env, StargateError::InvalidConfiguration);
        }

        admin.require_auth();

        let config = ConfigV1 {
            admin: admin.clone(),
            authority: authority.clone(),
        };
        storage.set(&key, &config);

        StargateInitialized {
            admin: config.admin,
            authority: config.authority,
        }
        .publish(env);
    }

    /// Returns the configured Stargate authority.
    ///
    /// Aborts with `NotInitialized` when configuration is missing.
    pub fn authority(env: &Env) -> Address {
        Self::load_config(env).authority
    }

    /// Requires Stargate authorization for the current contract invocation.
    pub fn require_authorized(env: &Env) {
        Self::authority(env).require_auth();
    }

    /// Replaces the authority with the approval of the administrator and successor.
    ///
    /// The expected authority must match the account currently in storage.
    pub fn rotate_authority(env: &Env, expected_authority: &Address, new_authority: &Address) {
        let mut config = Self::load_config(env);

        if &config.authority != expected_authority {
            panic_with_error!(env, StargateError::AuthorityChanged);
        }

        if new_authority == expected_authority
            || new_authority == &config.admin
            || !matches!(new_authority.executable(), Some(Executable::Account))
        {
            panic_with_error!(env, StargateError::InvalidConfiguration);
        }

        config.admin.require_auth();
        new_authority.require_auth();

        config.authority = new_authority.clone();
        env.storage()
            .instance()
            .set(&StorageKey::StargateConfig, &config);

        StargateAuthorityRotated {
            previous_authority: expected_authority.clone(),
            new_authority: config.authority,
        }
        .publish(env);
    }

    fn load_config(env: &Env) -> ConfigV1 {
        env.storage()
            .instance()
            .get(&StorageKey::StargateConfig)
            .unwrap_or_else(|| panic_with_error!(env, StargateError::NotInitialized))
    }
}

#[cfg(test)]
mod tests;
