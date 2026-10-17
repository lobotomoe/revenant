//! What the store listings show: the stores, their canvases, the shots, and the
//! fictional account every shot is staged with.

use std::path::{Path, PathBuf};

use revenant_sign_core::cms::{ByteRangeCoverage, SignatureStatus};
use revenant_sign_core::config::{ConfigStore, ServerProfile, SignerInfo, EKENG};
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::{CertInfo, TrustStatus};

use super::copy::{self, Locale, Text};
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

/// Where a store's listing carries each shot's copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CopyPlacement {
    /// Drawn above the window. App Store guideline 2.3.3 allows text overlays
    /// on screenshots that show the real app.
    OnImage,
    /// Kept off the image and written to `captions.txt` for the listing's
    /// per-screenshot caption field. Partner Center's screenshot guidance says
    /// not to add marketing messages to screenshots and offers a caption of up
    /// to 200 characters instead.
    Caption,
    /// Not shown at all. The Snap Store has no caption field, and its stated
    /// direction (and the Linux store norm, e.g. Flathub's rules) is to keep
    /// text out of screenshots.
    Omitted,
}

/// The longest caption Partner Center accepts per screenshot.
pub(crate) const CAPTION_LIMIT: usize = 200;

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

    /// The languages this store's listing is published in, each getting its
    /// own set of shots. Only Partner Center takes a set per language here: the
    /// App Store listings share one set, and the Snap Store has one listing.
    pub(crate) fn locales(self) -> &'static [Locale] {
        match self {
            Store::MacApp | Store::Snap => &[Locale::En],
            Store::Microsoft => &[Locale::En, Locale::Ru, Locale::Hy],
        }
    }

    pub(crate) fn copy(self) -> CopyPlacement {
        match self {
            Store::MacApp => CopyPlacement::OnImage,
            Store::Microsoft => CopyPlacement::Caption,
            Store::Snap => CopyPlacement::Omitted,
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
    headline: Text,
    subline: Text,
    setup: Setup,
    stage: fn(Locale) -> Stage,
}

/// Five shots: at most what the Snap Store takes, within the Microsoft Store's
/// recommended five to eight, and three of them the app at work -- App Store
/// guideline 2.3.3 approves a set only when more than half show the app in use
/// rather than a sign-in or setup screen.
pub(crate) const SHOTS: [Shot; 5] = [
    Shot {
        slug: "01-sign",
        headline: copy::SIGN_HEADLINE,
        subline: copy::SIGN_SUBLINE,
        setup: Setup::SignedIn,
        stage: |locale| Stage::Sign {
            pdf: PathBuf::from(copy::DOCUMENT.get(locale)),
        },
    },
    Shot {
        slug: "02-batch",
        headline: copy::BATCH_HEADLINE,
        subline: copy::BATCH_SUBLINE,
        setup: Setup::SignedIn,
        stage: |locale| Stage::SignMany {
            pdfs: copy::BATCH
                .iter()
                .map(|name| PathBuf::from(name.get(locale)))
                .collect(),
        },
    },
    Shot {
        slug: "03-verify",
        headline: copy::VERIFY_HEADLINE,
        subline: copy::VERIFY_SUBLINE,
        setup: Setup::SignedIn,
        stage: verify_stage,
    },
    Shot {
        slug: "04-server",
        headline: copy::SERVER_HEADLINE,
        subline: copy::SERVER_SUBLINE,
        setup: Setup::Fresh,
        stage: |_| Stage::ChooseServer,
    },
    Shot {
        slug: "05-login",
        headline: copy::LOGIN_HEADLINE,
        subline: copy::LOGIN_SUBLINE,
        setup: Setup::CredentialsSaved,
        stage: |_| Stage::LogIn {
            identity: certificate(),
        },
    },
];

impl Shot {
    pub(crate) fn headline(&self, locale: Locale) -> &'static str {
        self.headline.get(locale)
    }

    pub(crate) fn subline(&self, locale: Locale) -> &'static str {
        self.subline.get(locale)
    }

    /// The headline and subline as one caption.
    pub(crate) fn caption(&self, locale: Locale) -> String {
        let headline = self.headline(locale);
        let subline = self.subline(locale);
        let full_stop = locale.full_stop();
        format!("{headline}{full_stop} {subline}")
    }

    pub(crate) fn stage(&self, locale: Locale) -> Stage {
        (self.stage)(locale)
    }

    /// Build the isolated config store this shot is staged with, rooted in
    /// `dir`, naming `store`'s keychain and showing the app in `locale`.
    pub(crate) fn config_store(
        &self,
        dir: &Path,
        store: Store,
        locale: Locale,
    ) -> Result<ConfigStore, ScreenshotError> {
        let config = ConfigStore::isolated(dir.to_path_buf(), store.keychain_name());
        config.save_language(locale.code())?;
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
fn verify_stage(locale: Locale) -> Stage {
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
        pdf: PathBuf::from(copy::SIGNED_DOCUMENT.get(locale)),
        results: vec![result],
        server: Some(server),
    }
}
