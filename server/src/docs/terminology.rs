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
//!   their handle. In our code, stored in `OAuthTokenSet.did`.
//!
//! * **Handle**: The user's username in the Bluesky network, prefixed with '@'.
//!   Example: `@alice.bsky.social`. This is what other users type to mention someone.
//!   Unlike display names, handles must be unique across the network.
//!   Note: We don't directly store this in our database as we focus on display name.
//!
//! * **Display Name**: The user's chosen display name in Bluesky. This is the name shown
//!   prominently in the UI and can include spaces, emoji, and special characters.
//!   Example: "Alice 🌸". In our code, stored in `OAuthTokenSet.display_name`.
//!   For our profile picture progress feature, users include progress indicators
//!   (like "50%" or "3/10") in their display name.
//!
//! ## Authentication Terms
//!
//! * **OAuth Token**: An access token obtained through the OAuth flow with Bluesky.
//!   Stored in `OAuthTokenSet.access_token`.
//!
//! * **Refresh Token**: Used to obtain a new OAuth token when the current one expires.
//!   Stored in `OAuthTokenSet.refresh_token`.
//!
//! * **Session**: A user's authenticated session on our platform. Sessions are linked to a
//!   primary OAuth token but can have multiple tokens associated with a single user.
//!
//! * **DPoP (Demonstrating Proof-of-Possession)**: A security mechanism used by Bluesky's
//!   authentication system to prove possession of a private key corresponding to the
//!   public key used during authentication.
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
//! * **Primary Token**: The main OAuth token associated with a user's session, used for
//!   API operations and to display profile information.
