//! What the store listings show: the stores, their canvases, the shots, and the
//! fictional account every shot is staged with.

use std::path::{Path, PathBuf};

use revenant_sign_core::cms::{ByteRangeCoverage, SignatureStatus};
use revenant_sign_core::config::{ConfigStore, ServerProfile, SignerInfo, EKENG};
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::{CertInfo, TrustStatus};

use super::ScreenshotError;
use crate::app::stage::Stage;

/// A store the release publishes screenshots for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Store {
    MacApp,
    Microsoft,
    Snap,
}

/// Which operating system's window frame a store's screenshots wear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Chrome {
    MacOs,
    Windows,
    Gnome,
}

/// The app window size, in points, every shot is rendered at: the default
/// window's width, a little taller so the batch list and the Sign button fit on
/// screen together. A size the user can resize the window to, not a new layout.
pub(crate) const WINDOW_SIZE: [f32; 2] = [940.0, 800.0];

impl Store {
    pub(crate) const ALL: [Store; 3] = [Store::MacApp, Store::Microsoft, Store::Snap];

    /// Output directory name for this store's screenshots.
    pub(crate) fn dir_name(self) -> &'static str {
        match self {
            Store::MacApp => "mac-app-store",
            Store::Microsoft => "microsoft-store",
            Store::Snap => "snap-store",
        }
    }

    /// The canvas in pixels.
    ///
    /// - Mac App Store: 2880x1800, the largest of the four 16:10 sizes App
    ///   Store Connect accepts.
    /// - Microsoft Store: 3840x2160, the 4K desktop size Partner Center takes
    ///   (minimum 1366x768, PNG up to 50 MB).
    /// - Snap Store: 1920x1080. The listing caps each image at 2 MB and
    ///   3840x2160, and a gradient this large compresses past 2 MB above 1080p.
    pub(crate) fn canvas(self) -> [u16; 2] {
        match self {
            Store::MacApp => [2880, 1800],
            Store::Microsoft => [3840, 2160],
            Store::Snap => [1920, 1080],
        }
    }

    /// What the app calls the system keychain on this store's platform. Must
    /// read exactly as the core's keyring backend names it there.
    pub(crate) fn keychain_name(self) -> &'static str {
        match self {
            Store::MacApp => "macOS Keychain",
            Store::Microsoft => "Windows Credential Manager",
            Store::Snap => "Linux Secret Service",
        }
    }

    pub(crate) fn chrome(self) -> Chrome {
        match self {
            Store::MacApp => Chrome::MacOs,
            Store::Microsoft => Chrome::Windows,
            Store::Snap => Chrome::Gnome,
        }
    }
}

/// How far the fictional account is set up before a shot is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Setup {
    /// A fresh install.
    Fresh,
    /// EKENG chosen and credentials saved, identity not yet confirmed.
    CredentialsSaved,
    /// Fully configured: server, credentials, and signer identity.
    SignedIn,
}

/// One screenshot: the copy above the window and the app state inside it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Shot {
    /// File-name stem, prefixed with the shot's position so stores that keep
    /// upload order get the intended sequence.
    pub(crate) slug: &'static str,
    pub(crate) headline: &'static str,
    pub(crate) subline: &'static str,
    setup: Setup,
    stage: fn() -> Stage,
}

/// Five shots: at most what the Snap Store takes, within the Microsoft Store's
/// recommended five to eight, and three of them the app at work -- App Store
/// guideline 2.3.3 approves a set only when more than half show the app in use
/// rather than a sign-in or setup screen.
pub(crate) const SHOTS: [Shot; 5] = [
    Shot {
        slug: "01-sign",
        headline: "Sign PDFs with your CoSign account",
        subline: "Embedded or detached signatures, with a visible stamp on any page.",
        setup: Setup::SignedIn,
        stage: || Stage::Sign {
            pdf: PathBuf::from(DOCUMENT),
        },
    },
    Shot {
        slug: "02-batch",
        headline: "Sign a whole stack at once",
        subline: "Drop several PDFs and sign them all in one pass.",
        setup: Setup::SignedIn,
        stage: || Stage::SignMany {
            pdfs: BATCH.iter().map(PathBuf::from).collect(),
        },
    },
    Shot {
        slug: "03-verify",
        headline: "Verify signed PDFs",
        subline: "Integrity, signer, and certificate trust, checked in one step.",
        setup: Setup::SignedIn,
        stage: verify_stage,
    },
    Shot {
        slug: "04-server",
        headline: "EKENG profile built in",
        subline: "Or connect to any CoSign / DocuSign Signature Appliance server.",
        setup: Setup::Fresh,
        stage: || Stage::ChooseServer,
    },
    Shot {
        slug: "05-login",
        headline: "Your password, kept by the system keychain",
        subline: "Opt in once, and the operating system stores it for you.",
        setup: Setup::CredentialsSaved,
        stage: || Stage::LogIn {
            identity: certificate(),
        },
    },
];

impl Shot {
    pub(crate) fn stage(&self) -> Stage {
        (self.stage)()
    }

    /// Build the isolated config store this shot is staged with, rooted in
    /// `dir` and naming `store`'s keychain.
    pub(crate) fn config_store(
        &self,
        dir: &Path,
        store: Store,
    ) -> Result<ConfigStore, ScreenshotError> {
        let config = ConfigStore::isolated(dir.to_path_buf(), store.keychain_name());
        if self.setup == Setup::Fresh {
            return Ok(config);
        }
        let profile = ServerProfile::builtin(EKENG)?;
        config.save_server_config(&profile)?;
        config.save_credentials(USERNAME, PASSWORD)?;
        if self.setup == Setup::SignedIn {
            config.save_signer_info(&signer())?;
        }
        Ok(config)
    }
}

// -- The fictional account ----------------------------------------------------
//
// Every person, number and address below is made up; nothing in a screenshot
// comes from a real certificate or a real login.

const USERNAME: &str = "anna.petrosyan";
const PASSWORD: &str = "not-a-real-password";
/// An EKENG certificate CN: the holder's name followed by their SSN, which the
/// profile's field rules split into the Name and SSN rows.
const CERT_NAME: &str = "ANNA PETROSYAN 1234567890";
const EMAIL: &str = "anna.petrosyan@example.am";
const CERT_ISSUED: &str = "2025-03-01T00:00:00Z";
const CERT_EXPIRES: &str = "2028-03-01T00:00:00Z";
const DOCUMENT: &str = "Lease agreement.pdf";
const SIGNED_DOCUMENT: &str = "Lease agreement_signed.pdf";
const BATCH: [&str; 3] = [
    "Lease agreement.pdf",
    "Annex 1 - Inventory.pdf",
    "Annex 2 - Payment schedule.pdf",
];
const SIGNED_AT: &str = "2026-10-15T11:42:07Z";
const SIGNED_DOCUMENT_BYTES: usize = 184_320;
const TRUST_ANCHOR: &str = "Staff of Government of RA Root CA";

fn signer() -> SignerInfo {
    SignerInfo {
        name: Some(CERT_NAME.to_owned()),
        email: Some(EMAIL.to_owned()),
        organization: None,
        dn: Some(dn()),
        not_before: Some(CERT_ISSUED.to_owned()),
        not_after: Some(CERT_EXPIRES.to_owned()),
    }
}

/// The fictional account's signing certificate, as discovery and verification
/// read it.
fn certificate() -> CertInfo {
    CertInfo {
        name: Some(CERT_NAME.to_owned()),
        email: Some(EMAIL.to_owned()),
        organization: None,
        dn: Some(dn()),
        not_before: Some(CERT_ISSUED.to_owned()),
        not_after: Some(CERT_EXPIRES.to_owned()),
    }
}

fn dn() -> String {
    format!("CN={CERT_NAME}, E={EMAIL}, C=AM")
}

/// A finished report for a document the fictional account signed: what the
/// verify tab shows for a genuine, untouched EKENG signature.
fn verify_stage() -> Stage {
    let result = VerificationResult {
        structure_ok: true,
        hash_ok: true,
        signature: SignatureStatus::Valid,
        coverage: ByteRangeCoverage::whole(SIGNED_DOCUMENT_BYTES),
        ltv_enabled: false,
        details: Vec::new(),
        signer: Some(certificate()),
        trust_anchor: Some(TRUST_ANCHOR.to_owned()),
        trust_status: Some(TrustStatus::Trusted),
    };
    let server = ServerVerifyResult::Verified {
        signer_name: Some(CERT_NAME.to_owned()),
        sign_time: Some(SIGNED_AT.to_owned()),
        certificate_status: Some("Valid".to_owned()),
    };
    Stage::Verify {
        pdf: PathBuf::from(SIGNED_DOCUMENT),
        results: vec![result],
        server: Some(server),
    }
}
