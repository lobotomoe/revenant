//! Staged UI states for rendering the app-store screenshots.
//!
//! Each [`Stage`] puts the real app into one screen a store listing shows,
//! through the same entry points a user's actions reach (`set_pdf`, the login
//! wizard's keychain prefill, a finished verification report), so the
//! screenshots cannot drift from the shipped UI. The account itself -- server,
//! signer identity, saved credentials -- comes from the config store passed in.

use std::path::PathBuf;

use revenant_sign_core::config::ConfigStore;
use revenant_sign_core::net::ServerVerifyResult;
use revenant_sign_core::pdf::VerificationResult;
use revenant_sign_core::pki::CertInfo;

use super::{Dialog, RevenantApp, Tab};
use crate::views::LoginState;
use crate::window_style::WindowStyle;

/// One screen of the app as a store screenshot shows it.
pub(crate) enum Stage {
    /// The sign tab with a document loaded and ready to sign.
    Sign { pdf: PathBuf },
    /// The sign tab with several documents queued for one batch.
    SignMany { pdfs: Vec<PathBuf> },
    /// The verify tab showing a finished report for `pdf`.
    Verify {
        pdf: PathBuf,
        results: Vec<VerificationResult>,
        server: Option<ServerVerifyResult>,
    },
    /// The server picker, as a fresh install opens it.
    ChooseServer,
    /// The login wizard's summary page, with `identity` discovered and the
    /// saved credentials filled in.
    LogIn { identity: CertInfo },
}

impl RevenantApp {
    /// Build the app over `store`, framed as `window_style`, and bring it to
    /// `stage`.
    pub(crate) fn staged(
        cc: &eframe::CreationContext<'_>,
        store: ConfigStore,
        stage: Stage,
        window_style: WindowStyle,
    ) -> Self {
        let mut app = Self::with_store(cc, store, window_style);
        match stage {
            Stage::Sign { pdf } => app.sign_form.set_pdf(&pdf),
            Stage::SignMany { pdfs } => app.sign_form.set_files(pdfs),
            Stage::Verify {
                pdf,
                results,
                server,
            } => {
                app.tab = Tab::Verify;
                app.verify.set_pdf(&pdf);
                app.verify.on_done(Ok(results), server);
            }
            Stage::ChooseServer => app.dialog = Some(Dialog::Connect),
            Stage::LogIn { identity } => app.open_login_at_summary(identity),
        }
        app
    }

    /// Open the login wizard, fill in the saved password, and advance it to the
    /// summary page with `identity` as the discovered signer.
    ///
    /// [`RevenantApp::open_login`] reads the keychain on the worker so a locked
    /// keychain cannot stall the UI, which makes the moment the password lands
    /// timing-dependent. A screenshot needs it settled before the first frame,
    /// so this runs the same read and the same prefill path synchronously.
    fn open_login_at_summary(&mut self, identity: CertInfo) {
        let Some(profile) = self.store.active_profile() else {
            panic!("the login stage needs a configured server in its store");
        };
        let Some(username) = self.store.saved_username() else {
            panic!("the login stage needs saved credentials in its store");
        };
        let Some(password) = self.store.get_credentials().password else {
            panic!("the login stage needs a saved password in its store");
        };
        let storage_info = self.store.credential_storage_info();
        let mut login = LoginState::new(profile, Some(username.clone()), storage_info);
        let request = self.requests.issue();
        login.expect_prefill(request);
        login.prefill_password(request, &username, password.expose().to_owned());
        login.show_summary_for(identity);
        self.login = Some(login);
        self.dialog = Some(Dialog::Login);
    }
}
