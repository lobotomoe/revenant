//! View layer: each module renders one screen or dialog and returns an intent
//! for the app to act on, keeping side effects (config writes, worker spawns)
//! out of the render code.

pub(crate) mod about;
pub(crate) mod connect;
pub(crate) mod login;
pub(crate) mod settings;
pub(crate) mod sign;
pub(crate) mod verify;

pub(crate) use connect::{ConnectAction, ConnectState};
pub(crate) use login::{LoginAction, LoginState};
pub(crate) use settings::SettingsAction;
pub(crate) use sign::SignAction;
