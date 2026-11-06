use super::{ConfigV1, StargateError, StargateGuard, StorageKey};
use soroban_sdk::{
    Address, Env, IntoVal, TryFromVal, contract, contractimpl,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    xdr::{
        AccountId, Asset, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
        SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
        SorobanCredentials,
    },
};

#[contract]
struct TestContract;

#[contractimpl]
impl TestContract {
    pub fn __constructor(env: Env, admin: Address, authority: Address) {
        StargateGuard::initialize(&env, &admin, &authority);
    }

    pub fn reinitialize(env: Env, admin: Address, authority: Address) -> Result<(), StargateError> {
        StargateGuard::initialize(&env, &admin, &authority);
        Ok(())
    }

    pub fn protected(env: Env, amount: u32) -> u32 {
        StargateGuard::require_authorized(&env);
        amount
    }

    pub fn rotate_authority(
        env: Env,
        expected_authority: Address,
        new_authority: Address,
    ) -> Result<(), StargateError> {
        StargateGuard::rotate_authority(&env, &expected_authority, &new_authority);
        Ok(())
    }

    pub fn protected_for_user(env: Env, user: Address, amount: u32) -> u32 {
        StargateGuard::require_authorized(&env);
        user.require_auth();
        amount
    }
}

fn setup() -> (Env, Address, Address, Address) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let Asset::CreditAlphanum4(asset) = asset_contract.asset() else {
        panic!("expected a test asset with an issuer");
    };
    let authority = Address::try_from_val(&env, &ScAddress::Account(asset.issuer)).unwrap();
    let contract = env.register(TestContract, (admin.clone(), authority.clone()));

    (env, contract, admin, authority)
}

#[test]
fn constructor_stores_configuration() {
    let (env, contract, admin, authority) = setup();

    env.as_contract(&contract, || {
        let config: ConfigV1 = env
            .storage()
            .instance()
            .get(&StorageKey::StargateConfig)
            .unwrap();

        assert_eq!(config.admin, admin);
        assert_eq!(config.authority, authority);
    });
}

#[test]
fn rejects_repeated_initialization() {
    let (env, contract, admin, authority) = setup();
    let client = TestContractClient::new(&env, &contract);

    assert_eq!(
        client.try_reinitialize(&admin, &authority),
        Err(Ok(StargateError::AlreadyInitialized))
    );
}
#[test]
fn protected_call_requires_matching_stargate_authorization() {
    let (env, contract, _, authority) = setup();
    let client = TestContractClient::new(&env, &contract);
    let amount = 42_u32;

    let auth = [SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: (&contract).into(),
                function_name: ScSymbol(b"protected".to_vec().try_into().unwrap()),
                args: [ScVal::U32(amount)].to_vec().try_into().unwrap(),
            }),
            sub_invocations: Default::default(),
        },
    }];

    // The test environment starts with a different source account.
    assert!(client.set_auths(&auth).try_protected(&amount).is_err());

    env.host()
        .set_source_account(AccountId::try_from(&authority).unwrap())
        .unwrap();

    assert!(client.set_auths(&[]).try_protected(&amount).is_err());
    assert!(
        client
            .set_auths(&auth)
            .try_protected(&(amount + 1))
            .is_err()
    );
    assert_eq!(client.set_auths(&auth).protected(&amount), amount);
}

fn source_account_auth(
    contract: &Address,
    function_name: &str,
    args: &[ScVal],
) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::SourceAccount,
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: contract.into(),
                function_name: ScSymbol(function_name.as_bytes().to_vec().try_into().unwrap()),
                args: args.to_vec().try_into().unwrap(),
            }),
            sub_invocations: Default::default(),
        },
    }
}

#[test]
fn rotation_requires_both_approvals_and_replaces_the_authority() {
    let (env, contract, admin, old_authority) = setup();
    let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());
    let Asset::CreditAlphanum4(asset) = asset_contract.asset() else {
        panic!("expected a test asset with an issuer");
    };
    let new_authority = Address::try_from_val(&env, &ScAddress::Account(asset.issuer)).unwrap();
    let client = TestContractClient::new(&env, &contract);

    env.host()
        .set_source_account(AccountId::try_from(&new_authority).unwrap())
        .unwrap();

    let successor_auth = source_account_auth(
        &contract,
        "rotate_authority",
        &[
            ScVal::Address((&old_authority).into()),
            ScVal::Address((&new_authority).into()),
        ],
    );

    // Successor only.
    assert!(
        client
            .set_auths(core::slice::from_ref(&successor_auth))
            .try_rotate_authority(&old_authority, &new_authority)
            .is_err()
    );

    let admin_invocation = MockAuthInvoke {
        contract: &contract,
        fn_name: "rotate_authority",
        args: (&old_authority, &new_authority).into_val(&env),
        sub_invokes: &[],
    };
    let admin_mock = MockAuth {
        address: &admin,
        invoke: &admin_invocation,
    };

    // Register the mock administrator and try with its approval alone.
    env.mock_auths(core::slice::from_ref(&admin_mock));
    let admin_auth: SorobanAuthorizationEntry = admin_mock.into();
    assert!(
        client
            .set_auths(core::slice::from_ref(&admin_auth))
            .try_rotate_authority(&old_authority, &new_authority)
            .is_err()
    );
    env.as_contract(&contract, || {
        assert_eq!(StargateGuard::authority(&env), old_authority);
    });

    // Both approvals.
    client
        .set_auths(&[admin_auth, successor_auth])
        .rotate_authority(&old_authority, &new_authority);

    assert_eq!(
        client
            .set_auths(&[])
            .try_rotate_authority(&old_authority, &new_authority),
        Err(Ok(StargateError::AuthorityChanged))
    );

    let amount = 42_u32;
    let protected_auth = [source_account_auth(
        &contract,
        "protected",
        &[ScVal::U32(amount)],
    )];
    assert_eq!(client.set_auths(&protected_auth).protected(&amount), amount);

    env.host()
        .set_source_account(AccountId::try_from(&old_authority).unwrap())
        .unwrap();
    assert!(
        client
            .set_auths(&protected_auth)
            .try_protected(&amount)
            .is_err()
    );
}

#[test]
fn protected_call_requires_both_stargate_and_user_authorization() {
    let (env, contract, _, authority) = setup();
    let client = TestContractClient::new(&env, &contract);
    let user = Address::generate(&env);
    let amount = 42_u32;

    env.host()
        .set_source_account(AccountId::try_from(&authority).unwrap())
        .unwrap();

    let stargate_auth = source_account_auth(
        &contract,
        "protected_for_user",
        &[ScVal::Address((&user).into()), ScVal::U32(amount)],
    );

    let user_invocation = MockAuthInvoke {
        contract: &contract,
        fn_name: "protected_for_user",
        args: (&user, amount).into_val(&env),
        sub_invokes: &[],
    };
    let user_mock = MockAuth {
        address: &user,
        invoke: &user_invocation,
    };

    // Register the mock user contract, then supply auth explicitly for each call.
    env.mock_auths(core::slice::from_ref(&user_mock));
    let user_auth: SorobanAuthorizationEntry = user_mock.into();

    assert!(
        client
            .set_auths(&[])
            .try_protected_for_user(&user, &amount)
            .is_err()
    );
    assert!(
        client
            .set_auths(core::slice::from_ref(&stargate_auth))
            .try_protected_for_user(&user, &amount)
            .is_err()
    );
    assert!(
        client
            .set_auths(core::slice::from_ref(&user_auth))
            .try_protected_for_user(&user, &amount)
            .is_err()
    );
    assert_eq!(
        client
            .set_auths(&[stargate_auth, user_auth])
            .protected_for_user(&user, &amount),
        amount
    );
}

#[test]
fn protected_call_fails_closed_when_configuration_is_missing() {
    let (env, contract, _, authority) = setup();
    let amount = 42_u32;

    env.as_contract(&contract, || {
        env.storage().instance().remove(&StorageKey::StargateConfig);
    });

    env.host()
        .set_source_account(AccountId::try_from(&authority).unwrap())
        .unwrap();

    let auth = [source_account_auth(
        &contract,
        "protected",
        &[ScVal::U32(amount)],
    )];
    env.set_auths(&auth);

    let result = env.try_invoke_contract::<u32, StargateError>(
        &contract,
        &soroban_sdk::symbol_short!("protected"),
        (amount,).into_val(&env),
    );

    assert_eq!(result, Err(Ok(StargateError::NotInitialized)));
}

#[test]
fn rotation_rejects_invalid_replacements_without_changing_authority() {
    let (env, contract, admin, authority) = setup();
    let client = TestContractClient::new(&env, &contract);
    let asset_contract = env.register_stellar_asset_contract_v2(admin.clone());

    let contract_address = asset_contract.address();
    for (case, replacement) in [
        ("current authority", &authority),
        ("administrator", &admin),
        ("Stellar Asset Contract", &contract_address),
    ] {
        assert_eq!(
            client
                .set_auths(&[])
                .try_rotate_authority(&authority, replacement),
            Err(Ok(StargateError::InvalidConfiguration)),
            "replacement: {case}",
        );
    }

    env.as_contract(&contract, || {
        assert_eq!(StargateGuard::authority(&env), authority);
    });
}
