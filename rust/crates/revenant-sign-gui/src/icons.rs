//! Named aliases for the Phosphor icon glyphs used in the UI, so call sites read
//! as `icons::SIGN` rather than a raw `egui_phosphor` path. Each is a `&str`
//! holding a single private-use code point rendered by the bundled icon font
//! (installed in [`crate::fonts`]).

pub(crate) use egui_phosphor::regular::{
    ARROW_LEFT, ARROW_RIGHT, BUILDINGS as ORG, CARET_DOWN, CHECK_CIRCLE as SUCCESS,
    ENVELOPE as EMAIL, EYE_SLASH as INVISIBLE, FILE_PDF as PDF, GEAR_SIX as SETTINGS,
    HARD_DRIVES as SERVER, IMAGE, INFO as ABOUT, KEY as LOGIN, PEN_NIB as SIGN,
    PLUGS_CONNECTED as CONNECT, SHIELD_CHECK as VERIFY, SIGN_OUT as LOG_OUT, TRANSLATE as LANGUAGE,
    USER as NAME, WARNING as CAUTION, X as REMOVE, X_CIRCLE as FAILURE,
};
