//! Gestion des routes nécessitant une authentification utilisateur.

use axum::{
    extract::{Multipart, Query},
    response::{Html, IntoResponse},
    Json, Extension,
};
use anyhow::anyhow;
use handlebars::Handlebars;
use http::StatusCode;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
    sync::{Arc, RwLock},
};
use uuid::Uuid;
use crate::consts;
use crate::utils::error_messages::POST_FAILED;
use crate::utils::validation::{EmailInput, TextInput, FileInput};


/// Modèle représentant un post avec des likes
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Post {
    pub id: Uuid,
    pub content: String,
    pub image_path: Option<String>,
    pub likes: i32,
}

/// Base de données statique pour les posts (simulée en mémoire)
static POSTS: Lazy<RwLock<Vec<Post>>> = Lazy::new(|| {
    RwLock::new(vec![])
});

/// Affiche la page principale avec la liste des posts
pub async fn home(
    Extension(hbs): Extension<Arc<Handlebars<'_>>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let user = params.get("user").cloned().unwrap_or_else(|| "Guest".to_string());
    let data = json!({
        "user": user,
        "posts": *POSTS.read().unwrap(),
    });

    match hbs.render("home", &data) {
        Ok(body) => Html(body),
        Err(_) => Html("<h1>Internal Server Error</h1>".to_string()),
    }
}

/// Crée un nouveau post avec texte et image
pub async fn create_post(mut multipart: Multipart) -> axum::response::Result<Json<serde_json::Value>> {
    // We'll store our validated inputs rather than raw strings
    let mut text_content: Option<TextInput> = None;
    let mut file_content: Option<FileInput> = None;

    // Process each field from the multipart form
    while let Some(field) = multipart.next_field().await.map_err(|e| {
        (StatusCode::BAD_REQUEST, POST_FAILED)
    })? {
        let field_name = field.name()
            .ok_or((StatusCode::BAD_REQUEST, POST_FAILED))?
            .to_string();
        match field_name.as_str() {
            "text" => {
                // Extract and validate the text content
                let raw_text = field.text().await
                    .map_err(|_| (StatusCode::BAD_REQUEST, POST_FAILED))?;

                // Create a validated TextContent instance
                let validated_text = TextInput::new_long_form(&raw_text)
                    .map_err(|_| (StatusCode::BAD_REQUEST, POST_FAILED))?;

                text_content = Some(validated_text);
            }
            "file" => {
                // Extract file information
                let filename = field.file_name()
                    .ok_or((StatusCode::BAD_REQUEST, POST_FAILED))?
                    .to_string();

                let file_bytes = field.bytes().await
                    .map_err(|_| (StatusCode::BAD_REQUEST, POST_FAILED))?;

                // Create a validated FileContent instance
                let validated_file = FileInput::new(&file_bytes, &filename)
                    .map_err(|_| (StatusCode::BAD_REQUEST, POST_FAILED))?;

                // Create the uploads directory if it doesn't exist
                let uploads_dir = Path::new(consts::UPLOADS_DIR);
                tokio::fs::create_dir_all(uploads_dir)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, POST_FAILED))?;

                // Generate a unique filename to prevent collisions
                let unique_filename = format!("{}-{}",
                                              Uuid::new_v4(),
                                              validated_file.filename()
                );

                let file_path = uploads_dir.join(&unique_filename);

                // Write the validated file content
                tokio::fs::write(&file_path, validated_file.content())
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, POST_FAILED))?;

                file_content = Some(validated_file);
            }
            _ => continue, // Ignore unknown fields
        }
    }

    // Get the required text content
    let text = text_content.ok_or((
        StatusCode::BAD_REQUEST,
        "Text content is required"
    ))?;

    // Get the relative path for the frontend if a file was uploaded
    let image_path = if let Some(file) = file_content {
        Some(format!("{}/{}-{}",
                     consts::UPLOADS_DIR,
                     Uuid::new_v4(),
                     file.filename()
        ))
    } else {
        None
    };

    // Save the post with validated content
    let post_id = save_post(text.as_ref(), image_path.as_deref());

    Ok(Json(json!({ "post_id": post_id })))
}

/// Sauvegarde des posts dans un fichier YAML
pub fn save_posts_to_file() -> Result<(), anyhow::Error> {
    let posts = POSTS.read().map_err(|_| anyhow!("Failed to read posts"))?; // Lecture des posts existants
    let file_path = consts::POSTS_DB_PATH;
    let file_dir = Path::new(file_path).parent().unwrap();

    if !file_dir.exists() {
        create_dir_all(file_dir).or(Err(anyhow!("Failed to create directory for posts.")))?;
    }

    let file = File::create(file_path).or(Err(anyhow!("Failed to create posts.yaml.")))?;
    serde_yaml::to_writer(file, &*posts).or(Err(anyhow!("Failed to serialize posts to YAML.")))?;
    Ok(())
}

/// Charge les posts depuis un fichier YAML
pub fn load_posts_from_file() -> Result<(), anyhow::Error> {
    let file_path = consts::POSTS_DB_PATH;

    if Path::new(file_path).exists() {
        let file = File::open(file_path).or(Err(anyhow!("Failed to open posts.yaml.")))?;
        let loaded_posts: Vec<Post> = serde_yaml::from_reader(file).unwrap_or_default();

        let mut posts = POSTS.write().map_err(|_| anyhow!("Failed to write posts"))?;
        *posts = loaded_posts;
    }

    Ok(())
}

/// Simule la sauvegarde d'un post dans une base de données
fn save_post(text: &str, image_path: Option<&str>) -> String {
    let new_post = Post {
        id: Uuid::new_v4(),
        content: text.to_string(),
        image_path: image_path.map(|path| path.to_string()),
        likes: 0,
    };

    let post_id = new_post.id.to_string();

    {
        let mut posts = POSTS.write().unwrap();
        posts.push(new_post);
    }

    if let Err(e) = save_posts_to_file() {
        eprintln!("Failed to save posts: {}", e);
    }

    post_id
}

/// Permet de like un post
pub async fn like_post(Json(body): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {
    let post_id = body
        .get("post_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Post ID is required"))?;
    let post_id = Uuid::parse_str(post_id).map_err(|_| (StatusCode::BAD_REQUEST, "Invalid Post ID"))?;

    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Action is required"))?;

    let mut posts = POSTS.write().map_err(|_| (StatusCode::BAD_REQUEST, "Failed to write posts"))?;
    let post = posts.iter_mut().find(|post| post.id == post_id);

    if let Some(post) = post {
        match action {
            "like" => {
                if post.likes == 1 {
                    post.likes = 0;
                } else {
                    post.likes = 1;
                }
            }
            "dislike" => {
                if post.likes == -1 {
                    post.likes = 0;
                } else {
                    post.likes = -1;
                }
            }
            _ => return Err((StatusCode::BAD_REQUEST, "Invalid action").into()),
        }
        return Ok(StatusCode::OK);
    }

    Err((StatusCode::NOT_FOUND, "Post not found").into())
}
