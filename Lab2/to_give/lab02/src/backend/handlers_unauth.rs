//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use axum::{
    extract::{Path, Json, Query},
    response::{Redirect, IntoResponse, Html},
    http::StatusCode,
};

use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, RegisterPublicKeyCredential};
use crate::{database, HBS};
use crate::database::{user, token};
use crate::email::send_mail;
use crate::utils::error_messages::{AppError, LOGIN_ERROR, REGISTRATION_ERROR, RECOVER_ERROR};
use crate::utils::error_messages::AppError::Login;
use crate::utils::validation::{EmailInput, TextInput};
use crate::utils::webauthn::{begin_registration, complete_registration, begin_authentication, complete_authentication, StoredRegistrationState, CREDENTIAL_STORE};
use crate::database::*;

/// Structure pour gérer un état temporaire avec un challenge
struct TimedStoredState<T> {
    state: T,
    server_challenge: String,
}

/// Stockage des états d'enregistrement et d'authentification
pub(crate) static REGISTRATION_STATES: Lazy<RwLock<HashMap<String, StoredRegistrationState>>> =
    Lazy::new(Default::default);
static AUTHENTICATION_STATES: Lazy<RwLock<HashMap<String, TimedStoredState<PasskeyAuthentication>>>> = Lazy::new(Default::default);

/// Début du processus d'enregistrement WebAuthn
pub async fn register_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {

    // Extract and validate the email in steps for better error handling
    let raw_email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;


    // Create the validated email input, converting validation errors to appropriate HTTP responses
    let email = EmailInput::new(raw_email)
        .map_err(|_| (StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // First, we need to ensure the user's passkey is loaded if they exist
    let mut store = CREDENTIAL_STORE.write().await;
    if store.get(email.as_ref()).is_none() {
        if let Ok(Some(passkey)) = user::get_passkey(email.as_ref()) {
            store.insert(email.to_string(), passkey);
        }
    }
    drop(store); // Explicitly release the lock

    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);

    // Verify registration conditions based on reset mode
    match (reset_mode, user::exists(email.as_ref())) {
        (true, Ok(true)) => (), // Reset mode requires existing user
        (false, Ok(false)) => (), // Normal registration requires new user
        _ => return Err((StatusCode::BAD_REQUEST, REGISTRATION_ERROR).into()),
    }

    // Begin the registration process
    let (pk, registration_state) = begin_registration(email.as_ref(), email.as_ref())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, REGISTRATION_ERROR))?;

    // Generate a unique ID for this registration session
    let state_id = uuid::Uuid::new_v4().to_string();

    // Store the registration state
    REGISTRATION_STATES.write().await.insert(
        state_id.clone(),
        StoredRegistrationState {
            registration_state,
            challenge: pk["challenge"].as_str().unwrap_or_default().to_string(),
        },
    );

    Ok(Json(json!({
        "publicKey": pk,
        "state_id": state_id,
    })))
}

/// Fin du processus d'enregistrement WebAuthn
pub async fn register_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {

    // Extract and validate the email in steps
    let raw_email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Create the validated email input, converting validation errors to appropriate HTTP responses
    let email = EmailInput::new(raw_email)
        .map_err(|_| (StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    let reset_mode = payload.get("reset_mode").and_then(|v| v.as_bool()).unwrap_or(false);

    // Extract and validate first name and last name
    let raw_first_name = payload
        .get("first_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    let raw_last_name = payload
        .get("last_name")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Create the validated first name and last name input, converting validation errors to
    // appropriate HTTP responses
    let first_name = TextInput::new_short_form(raw_first_name)
        .map_err(|_| (StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    let last_name = TextInput::new_short_form(raw_last_name)
        .map_err(|_| (StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Get the stored state
    let raw_state_id = payload
        .get("state_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Validate the state id
    let state_id = TextInput::new_short_form(raw_state_id)
        .map_err(|_| (StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    let stored_state = REGISTRATION_STATES
        .write()
        .await
        .remove(state_id.as_ref())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Parse and validate the credential
    let cred = payload
        .get("response")
        .and_then(|v| serde_json::from_value::<RegisterPublicKeyCredential>(v.clone()).ok())
        .ok_or((StatusCode::BAD_REQUEST, REGISTRATION_ERROR))?;

    // Complete the registration
    complete_registration(email.as_ref(), &cred, &stored_state)
        .await
        .map_err(|_| (StatusCode::FORBIDDEN, REGISTRATION_ERROR))?;

    // Get the new passkey from the store
    let passkey = CREDENTIAL_STORE
        .read()
        .await
        .get(email.as_ref())
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, REGISTRATION_ERROR))?
        .clone();

    // Create or update user account
    if !reset_mode {
        user::create(email.as_ref(), first_name.as_ref(), last_name.as_ref())
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, REGISTRATION_ERROR))?;

       user::verify(email.as_ref())
           .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, REGISTRATION_ERROR))?;
    }

    // Save the passkey
    user::set_passkey(email.as_ref(), passkey)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to save passkey"))?;

    Ok(StatusCode::OK)
}

/// Début du processus d'authentification WebAuthn
pub async fn login_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {

    // Extract and validate the email in steps for better error handling
    let raw_email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, LOGIN_ERROR))?;

    // Create the validated email input, converting validation errors to appropriate HTTP responses
    let email = EmailInput::new(raw_email)
        .map_err(|_| (StatusCode::BAD_REQUEST, LOGIN_ERROR))?;

    // Load user's passkey if it exists
    let mut store = CREDENTIAL_STORE.write().await;
    if store.get(email.as_ref()).is_none() {
        if let Ok(Some(passkey)) = user::get_passkey(email.as_ref()) {
            store.insert(email.to_string(), passkey);
        }
    }
    drop(store);

    // Verify user exists and is verified
    match user::get(email.as_ref()) {
        Some(user_data) if !user_data.verified => {
            return Err((StatusCode::BAD_REQUEST, LOGIN_ERROR).into())
        }
        None => return Err((StatusCode::BAD_REQUEST, LOGIN_ERROR).into()),
        Some(_) => {}
    }

    // Begin authentication
    let (pk, state) = begin_authentication(email.as_ref())
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, LOGIN_ERROR))?;

    // Store authentication state
    let state_id = uuid::Uuid::new_v4().to_string();
    AUTHENTICATION_STATES.write().await.insert(
        state_id.clone(),
        TimedStoredState {
            state,
            server_challenge: pk["challenge"].as_str().unwrap_or_default().to_string(),
        },
    );

    Ok(Json(json!({
        "publicKey": pk,
        "state_id": state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Redirect> {
    // Parse and validate the credential response
    let cred: PublicKeyCredential = serde_json::from_value(
        payload
            .get("response")
            .ok_or((StatusCode::BAD_REQUEST, LOGIN_ERROR))?.clone()
    ).map_err(|_| (StatusCode::BAD_REQUEST, LOGIN_ERROR))?;

    // Get the stored state
    let state_id = payload
        .get("state_id")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, LOGIN_ERROR))?;

    let stored_state = AUTHENTICATION_STATES
        .write()
        .await
        .remove(state_id)
        .ok_or((StatusCode::BAD_REQUEST, LOGIN_ERROR))?;

    // Complete authentication
    complete_authentication(&cred, &stored_state.state, &stored_state.server_challenge)
        .await
        .map_err(|_| (StatusCode::FORBIDDEN, LOGIN_ERROR))?;

    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout() -> impl IntoResponse {
    Redirect::to("/")
}

/// Valide un compte utilisateur via un token
pub async fn validate_account(Path(token): Path<String>) -> impl IntoResponse {
    match token::consume(&token) {
        Ok(email) => match user::verify(&email) {
            Ok(_) => Redirect::to("/login?validated=true"),
            Err(_) => Redirect::to("/register?error=validation_failed"),
        },
        Err(_) => Redirect::to("/register?error=invalid_token"),
    }
}

/// Envoie un email de récupération de compte à l'utilisateur
pub async fn recover_account(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Html<String>> {


    // Extract and validate the email in steps for better error handling
    let raw_email = payload
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or((StatusCode::BAD_REQUEST, RECOVER_ERROR))?;

    // Create the validated email input, converting validation errors to appropriate HTTP responses
    let email = EmailInput::new(raw_email)
        .map_err(|_| (StatusCode::BAD_REQUEST, RECOVER_ERROR))?;

    let mut data = HashMap::new();
    data.insert("success", true);  // Always return success for security

    // Only send recovery email if user exists and is verified
    if let Some(user_data) = user::get(email.as_ref()) {
        if user_data.verified {
            if let Ok(recovery_token) = token::generate(email.as_ref()) {
                let recovery_link = format!("http://localhost:8080/recover/{}", recovery_token);

                // Send recovery email
                if let Err(e) = send_mail(
                    email.as_ref(),
                    "Account Recovery",
                    &format!(
                        "Click the following link to recover your account: {}\n\n\
                         If you did not request this recovery, you can safely ignore this email.",
                        recovery_link
                    ),
                ) {
                    log::error!("Failed to send recovery email: {}", e);
                }
            }
        }
    }

    HBS.render("recover", &data)
        .map(Html)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, RECOVER_ERROR).into())

}

/// Gère la réinitialisation du compte utilisateur via un token de récupération
pub async fn reset_account(Path(token): Path<String>) -> Html<String> {
    match token::consume(&token) {
        Ok(email) => {
            let redirect_url = format!("/register?reset_mode=true&email={}&success=true", email);
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
        Err(_) => {
            let redirect_url = "/register?error=recovery_failed";
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
    }
}

/// --- Affichage des pages ---
///
/// Affiche la page d'accueil
pub async fn index(session: tower_sessions::Session) -> impl IntoResponse {
    let is_logged_in = session.get::<String>("email").is_ok();
    let mut data = HashMap::new();
    data.insert("logged_in", is_logged_in);

    HBS.render("index", &data)
        .map(Html)
        .unwrap_or_else(|_| Html("Internal Server Error".to_string()))
}

/// Affiche la page de connexion
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../../templates/login.hbs"))
}

/// Affiche la page d'inscription avec des messages contextuels si présents
pub async fn register_page(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut context = HashMap::new();
    if let Some(success) = params.get("success") {
        if success == "true" {
            context.insert("success_message", "Account recovery successful. Please reset your passkey.");
        }
    }
    if let Some(error) = params.get("error") {
        if error == "recovery_failed" {
            context.insert("error_message", "Invalid or expired recovery link. Please try again.");
        }
    }

    HBS.render("register", &context)
        .map(Html)
        .unwrap_or_else(|_| Html("<h1>Internal Server Error</h1>".to_string()))
}

/// Affiche la page de récupération de compte
pub async fn recover_page() -> impl IntoResponse {
    Html(include_str!("../../templates/recover.hbs"))
}
