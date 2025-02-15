//! Gère l'intégration de WebAuthn pour l'enregistrement, l'authentification, et la récupération.
//! Fournit des fonctions pour démarrer et compléter les processus d'enregistrement et d'authentification.
//! Inclut également des mécanismes pour la gestion sécurisée des passkeys et des tokens de récupération.

use std::collections::HashMap;
use anyhow::{Result, Context};
use webauthn_rs::prelude::*;
use once_cell::sync::Lazy;
use url::Url;
use tokio::sync::RwLock;
use crate::database;
use crate::utils::error_messages::{AUTH_FAILED, REGISTRATION_ERROR};

// Initialisation globale de WebAuthn
static WEBAUTHN: Lazy<Webauthn> = Lazy::new(|| {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid RP origin URL");

    WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Failed to initialize WebAuthn")
        .build()
        .expect("Failed to build WebAuthn instance")
});

// Store sécurisé pour les passkeys
pub static CREDENTIAL_STORE: Lazy<RwLock<HashMap<String, Passkey>>> = Lazy::new(Default::default);

// Structure pour stocker l'état d'enregistrement
pub(crate) struct StoredRegistrationState {
    pub registration_state: PasskeyRegistration,
    pub challenge: String,
}

/// Démarrer l'enregistrement WebAuthn
pub async fn begin_registration(
    user_email: &str,
    user_display_name: &str,
) -> Result<(serde_json::Value, PasskeyRegistration)> {

    // Generate a unique identifier for this user that will persist even if they change their email
    let user_unique_id = Uuid::new_v4();

    // If the user has any other credentials, we exclude these here so they can't be duplicate registered.
    // It also hints to the browser that only new credentials should be "blinked" for interaction.
    let exclude_credentials = {
        CREDENTIAL_STORE
            .read()
            .await
            .get(user_email)
            .map(|passkey| vec![passkey.cred_id().clone()])
    };

    // Start the registration process with the WebAuthn instance
    let (ccr, reg_state) = WEBAUTHN
        .start_passkey_registration(
            user_unique_id,
            user_email,
            user_display_name,
            exclude_credentials,
        )
        .context(REGISTRATION_ERROR)?;

    Ok((
        serde_json::json!({
            "rp": ccr.public_key.rp,
            "user": {
                "id": ccr.public_key.user.id,
                "name": ccr.public_key.user.name,
                "displayName": ccr.public_key.user.display_name,
            },
            "challenge": ccr.public_key.challenge,
            "pubKeyCredParams": ccr.public_key.pub_key_cred_params,
            "timeout": ccr.public_key.timeout,
            "authenticatorSelection": ccr.public_key.authenticator_selection,
            "attestation": ccr.public_key.attestation_formats,
        }),
        reg_state,
    ))
}

/// Compléter l'enregistrement WebAuthn
pub async fn complete_registration(
    user_email: &str,
    response: &RegisterPublicKeyCredential,
    stored_state: &StoredRegistrationState,
) -> Result<()> {

    // Complete the registration
    let passkey = WEBAUTHN
        .finish_passkey_registration(
            response,
            &stored_state.registration_state,
        )
        .context("Failed to complete registration")?;


    // Store the passkey
    CREDENTIAL_STORE
        .write()
        .await
        .insert(user_email.to_string(), passkey);

    Ok(())
}

/// Démarrer l'authentification WebAuthn
pub async fn begin_authentication(user_email: &str) -> Result<(serde_json::Value, PasskeyAuthentication)> {

    // Get user's passkey
    let passkey = CREDENTIAL_STORE
        .read()
        .await
        .get(user_email)
        .map(|passkey| vec![passkey.clone()])
        .unwrap_or_default();


    // Start authentication
    let (rcr, state) = WEBAUTHN
        .start_passkey_authentication(&passkey)
        .context("Failed to start authentication")?;

    Ok((
        serde_json::json!({
            "challenge": rcr.public_key.challenge,
            "timeout": rcr.public_key.timeout,
            "rpId": rcr.public_key.rp_id,
            "allowCredentials": rcr.public_key.allow_credentials,
         }),
        state,
    ))
}

/// Compléter l'authentification WebAuthn
pub async fn complete_authentication(
    response: &PublicKeyCredential,
    state: &PasskeyAuthentication,
    server_challenge: &str,
) -> Result<()> {


    // Validate server challenge format (should be base64url encoded)
    if !server_challenge.chars().all(|c| {
        c.is_alphanumeric() || c == '-' || c == '_'
    }) {
        return Err(anyhow::anyhow!(AUTH_FAILED));
    }

    // Verify the client data
    let client_data_bytes = response.response.client_data_json.as_ref();
    let client_data_json = String::from_utf8(client_data_bytes.to_vec())
        .context("Failed to decode client_data_json")?;

    let client_data: serde_json::Value = serde_json::from_str(&client_data_json)
        .context("Failed to parse client_data_json")?;

    // Verify challenge matches
    let response_challenge = client_data["challenge"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!(AUTH_FAILED))?;

    if response_challenge != server_challenge {
        return Err(anyhow::anyhow!(AUTH_FAILED));
    }

    // Complete authentication
    WEBAUTHN
        .finish_passkey_authentication(response, state)
        .context(AUTH_FAILED)?;

    Ok(())
}
