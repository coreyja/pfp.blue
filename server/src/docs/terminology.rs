//! # Project Terminology
//!
//! This module documents key terminology used throughout the pfp.blue project.
//! Understanding these terms is essential for developers working with the codebase
//! and Bluesky protocol.
//!
//! ## Bluesky Identity Terms
//!
//! * **DID (Decentralized Identifier)**: The permanent, globally unique identifier for a user.
//!   Example: `did:plc:abcdefghijklmnopqrstuvwxy`. DIDs don't change even if a user changes
//!   their handle. Managed by the atrium OAuth system.
//!
//! * **Handle**: The user's username in the Bluesky network, prefixed with '@'.
//!   Example: `@alice.bsky.social`. This is what other users type to mention someone.
//!   Unlike display names, handles must be unique across the network.
//!
//! * **Display Name**: The user's chosen display name in Bluesky. This is the name shown
//!   prominently in the UI and can include spaces, emoji, and special characters.
//!   Example: "Alice 🌸". For our profile picture progress feature, users include progress 
//!   indicators (like "50%" or "3/10") in their display name.
//!
//! ## Authentication Terms
//!
//! * **OAuth Token**: An access token obtained through the OAuth flow with Bluesky using the
//!   atrium crate. These tokens are managed by `atrium_oauth::OAuthClient`.
//!
//! * **Refresh Token**: Used to obtain a new OAuth token when the current one expires.
//!   Handled automatically by the atrium OAuth system.
//!
//! * **Session**: A user's authenticated session on our platform. Sessions are managed by
//!   atrium's `DbSessionStore` and can be associated with multiple accounts.
//!
//! * **DPoP (Demonstrating Proof-of-Possession)**: A security mechanism used by Bluesky's
//!   authentication system to prove possession of a private key corresponding to the
//!   public key used during authentication. Handled by the atrium crate.
//!
//! ## Feature-specific Terms
//!
//! * **Profile Picture Progress**: Our feature that visualizes progress indicators from a user's
//!   display name as a circular overlay on their profile picture. Users can include progress
//!   in formats like "3/10" or "30%" in their display name.
//!
//! * **Original Blob CID**: The Content ID (CID) of the user's original profile picture
//!   stored in the Bluesky network. Used as the base for our progress visualization.
//!
//! ## Database Terms
//!
//! * **User**: Represents a user of our application who may have multiple Bluesky accounts
//!   (multiple DIDs) linked.
//!
//! * **Account**: Represents a single Bluesky account linked to a user. Stored in the
//!   `accounts` table with the associated DID and profile information.
