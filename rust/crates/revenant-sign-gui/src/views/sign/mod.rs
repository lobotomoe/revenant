//! Sign tab. Its content follows the config layer, mirroring the Python client:
//! prompt to connect, prompt to log in, or the signing form.
//!
//! The form itself ([`SignForm`]) is pure UI state; browsing files, spawning the
//! signing job, and revealing the result are side effects the app performs in
//! response to the returned [`SignAction`].

use std::path::{Path, PathBuf};

use eframe::egui;
use revenant_sign_core::config::{ConfigLayer, ConfigStore};
use revenant_sign_core::pdf::{PageSpec, Position};
use revenant_sign_core::signing::EmbeddedSignatureOptions;

use super::account::{self, AccountAction};
use crate::i18n::Localizer;
use crate::theme;

mod input;
mod options;
mod progress;

/// Minimum size of the Sign button.
const SIGN_BUTTON_MIN: [f32; 2] = [160.0, 32.0];

/// Below this available width, the settings/card section stacks instead of
/// splitting into two columns (egui has no automatic column reflow).
const TWO_COLUMN_MIN_WIDTH: f32 = 720.0;
/// Space between the sections of the form.
const SECTION_GAP: f32 = 20.0;

/// Bounds for the explicit page number (1-based in the UI, 0-based in
/// [`PageSpec::Index`]). The upper bound is a sanity cap, not a real PDF limit.
const MIN_PAGE: usize = 1;
const MAX_PAGE: usize = 9999;

/// What the app should do after rendering the tab.
pub(crate) enum SignAction {
    None,
    /// Open the connect dialog.
    Connect,
    /// Open the login wizard.
    Login,
    /// Open a native picker to choose the input PDF.
    BrowsePdf,
    /// Open a native picker to choose a stamp image.
    BrowseImage,
    /// Start signing the current form (single file or batch).
    Sign,
    /// Cancel an in-progress batch after the current file.
    CancelBatch,
}

/// Embedded (in-document) vs. detached (`.p7s`) signature.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Embedded,
    Detached,
}

/// Progress of a signing job, surfaced under the Sign button.
enum SignStatus {
    Idle,
    Signing,
    /// Success line (already localized).
    Done(String),
    /// Failure line (already localized or a raw error).
    Failed(String),
}

/// Progress of an in-flight batch run.
struct BatchProgress {
    /// 1-based index of the file currently being signed.
    current: usize,
    total: usize,
    filename: String,
}

/// Persistent state of the signing form (layer 2).
pub(crate) struct SignForm {
    pdf_path: String,
    image_path: String,
    mode: Mode,
    position: Position,
    page: PageSpec,
    /// Editing buffer for the explicit page-number field (1-based digits).
    page_input: String,
    font: String,
    invisible: bool,
    reason: String,
    status: SignStatus,
    /// Files queued for batch signing (>1 selects batch mode).
    batch: Vec<PathBuf>,
    /// Present while a batch run is in flight.
    batch_progress: Option<BatchProgress>,
}

impl SignForm {
    pub(crate) fn new(default_font: String) -> Self {
        Self {
            pdf_path: String::new(),
            image_path: String::new(),
            mode: Mode::Embedded,
            position: Position::BottomRight,
            page: PageSpec::Last,
            page_input: MIN_PAGE.to_string(),
            font: default_font,
            invisible: false,
            reason: String::new(),
            status: SignStatus::Idle,
            batch: Vec::new(),
            batch_progress: None,
        }
    }

    /// Set the input PDF (from the picker or a drop).
    pub(crate) fn set_pdf(&mut self, path: &Path) {
        self.pdf_path = path.to_string_lossy().into_owned();
        self.status = SignStatus::Idle;
    }

    /// Load one or more files: a single file uses the single-file field; several
    /// switch to batch mode.
    pub(crate) fn set_files(&mut self, mut paths: Vec<PathBuf>) {
        match paths.len() {
            0 => {}
            1 => {
                self.batch.clear();
                self.set_pdf(&paths.remove(0));
            }
            _ => {
                self.batch = paths;
                self.status = SignStatus::Idle;
                self.batch_progress = None;
            }
        }
    }

    pub(crate) fn is_batch(&self) -> bool {
        !self.batch.is_empty()
    }

    pub(crate) fn batch_files(&self) -> Vec<PathBuf> {
        self.batch.clone()
    }

    pub(crate) fn begin_batch(&mut self) {
        self.batch_progress = Some(BatchProgress {
            current: 0,
            total: self.batch.len(),
            filename: String::new(),
        });
        self.status = SignStatus::Idle;
    }

    pub(crate) fn on_batch_progress(&mut self, current: usize, total: usize, filename: String) {
        self.batch_progress = Some(BatchProgress {
            current,
            total,
            filename,
        });
    }

    pub(crate) fn on_batch_done(&mut self, message: String, ok: bool) {
        self.batch_progress = None;
        self.status = if ok {
            SignStatus::Done(message)
        } else {
            SignStatus::Failed(message)
        };
    }

    pub(crate) fn set_image(&mut self, path: &Path) {
        self.image_path = path.to_string_lossy().into_owned();
    }

    pub(crate) fn pdf_path(&self) -> &str {
        self.pdf_path.trim()
    }

    pub(crate) fn is_detached(&self) -> bool {
        self.mode == Mode::Detached
    }

    /// The default output path for the current PDF and mode: the name and folder
    /// the save dialog opens with. `None` until a PDF is set.
    pub(crate) fn default_output(&self) -> Option<PathBuf> {
        let pdf = self.pdf_path.trim();
        (!pdf.is_empty()).then(|| default_output(Path::new(pdf), self.is_detached()))
    }

    pub(crate) fn embedded_options(&self) -> EmbeddedSignatureOptions {
        let image = self.image_path.trim();
        EmbeddedSignatureOptions {
            page: self.page,
            position: self.position,
            reason: self.reason.trim().to_owned(),
            visible: !self.invisible,
            font: Some(self.font.clone()),
            image_path: (!image.is_empty()).then(|| image.to_owned()),
            ..Default::default()
        }
    }

    pub(crate) fn begin_signing(&mut self) {
        self.status = SignStatus::Signing;
    }

    pub(crate) fn on_signed_ok(&mut self, message: String) {
        self.status = SignStatus::Done(message);
    }

    pub(crate) fn on_signed_failed(&mut self, message: String) {
        self.status = SignStatus::Failed(message);
    }

    /// Drop a finished result line. The Done/Failed messages are pre-localized at
    /// sign time, so after a language switch they would show in the old language;
    /// clearing them avoids a stale, wrong-language line. A job in flight is left
    /// running.
    pub(crate) fn reset_result(&mut self) {
        if matches!(self.status, SignStatus::Done(_) | SignStatus::Failed(_)) {
            self.status = SignStatus::Idle;
        }
    }

    /// The fully-configured signing screen: input + image on top, then two
    /// columns (the signature options left, the signer right), then the Sign
    /// button at the bottom right with the result line beside it.
    fn ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer, store: &ConfigStore) -> SignScreen {
        let mut action = SignAction::None;
        let mut account_action = AccountAction::None;
        ui.add_space(8.0);

        // Top (full width): the file(s) to sign and the optional stamp image.
        let top = self.input_section(ui, l10n);
        merge(&mut action, top);

        ui.add_space(SECTION_GAP);

        // The options and the signer card sit side by side when there is room,
        // and stack when the window is too narrow -- egui does not reflow
        // columns on its own, so we pick the layout from the available width.
        // Captured before the columns: `ui.columns` can overflow and shift the
        // layout's content bounds, which would throw off the button row.
        let full_width = ui.available_width();
        if full_width >= TWO_COLUMN_MIN_WIDTH {
            ui.columns(2, |cols| {
                if let [left, right] = cols {
                    self.options(left, l10n);
                    account_action = account::show(right, l10n, store);
                }
            });
        } else {
            self.options(ui, l10n);
            ui.add_space(SECTION_GAP);
            account_action = account::show(ui, l10n, store);
        }

        // Bottom: the primary action at the trailing edge, where both macOS and
        // Windows put it, with the result of the last run beside it. Allocated
        // at the full width so a prior overflowing columns row cannot shift it.
        // The in-progress state is a full-window overlay instead, so it can't
        // be clipped off the bottom of the form.
        ui.add_space(SECTION_GAP);
        ui.allocate_ui_with_layout(
            egui::vec2(full_width, 0.0),
            egui::Layout::right_to_left(egui::Align::Center),
            |ui| {
                merge(&mut action, self.sign_button(ui, l10n));
                self.result_line(ui);
            },
        );
        merge(&mut action, self.progress_overlay(ui.ctx(), l10n));

        SignScreen {
            sign: action,
            account: account_action,
        }
    }

    /// The Sign button. Its label and gating follow the mode
    /// (single vs. batch, embedded vs. detached) and busy state.
    fn sign_button(&self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let busy = matches!(self.status, SignStatus::Signing) || self.batch_progress.is_some();
        let has_input = self.is_batch() || !self.pdf_path.trim().is_empty();
        let label = if self.is_batch() {
            l10n.tf("gui.sign_n_pdfs", &[("n", &self.batch.len().to_string())])
        } else if self.is_detached() {
            l10n.t("gui.sign_detached").to_owned()
        } else {
            l10n.t("gui.sign_pdf").to_owned()
        };
        let mut action = SignAction::None;
        let button = crate::style::primary_button(format!("{}  {label}", crate::icons::SIGN))
            .min_size(egui::vec2(SIGN_BUTTON_MIN[0], SIGN_BUTTON_MIN[1]));
        if ui.add_enabled(!busy && has_input, button).clicked() {
            action = SignAction::Sign;
        }
        action
    }

    /// Whether the visible-signature appearance controls apply (embedded and
    /// not marked invisible).
    fn appearance_enabled(&self) -> bool {
        !self.is_detached() && !self.invisible
    }

    /// Render the completed-result line (success or failure) beside the button.
    /// In-progress state lives in [`Self::progress_overlay`] instead.
    fn result_line(&self, ui: &mut egui::Ui) {
        match &self.status {
            SignStatus::Done(message) => {
                ui.colored_label(theme::OK, message);
            }
            SignStatus::Failed(message) => {
                ui.colored_label(theme::ERROR, message);
            }
            SignStatus::Idle | SignStatus::Signing => {}
        }
    }
}

/// `document.pdf` -> `document_signed.pdf`, or `document.pdf.p7s` when detached.
/// Matches the CLI's naming so the two clients agree on defaults.
pub(crate) fn default_output(pdf: &Path, detached: bool) -> PathBuf {
    if detached {
        pdf.with_extension("pdf.p7s")
    } else {
        let stem = pdf.file_stem().unwrap_or_default().to_string_lossy();
        pdf.with_file_name(format!("{stem}_signed.pdf"))
    }
}

/// The result of rendering the Sign tab: the signing intent plus any account-
/// panel intent (the latter only exists at the fully-configured layer).
pub(crate) struct SignScreen {
    pub(crate) sign: SignAction,
    pub(crate) account: AccountAction,
}

impl SignScreen {
    /// A screen with no account panel (the connect/login prompt layers).
    fn prompt_only(sign: SignAction) -> Self {
        Self {
            sign,
            account: AccountAction::None,
        }
    }
}

/// Keep the last non-`None` action, so a later section does not erase an intent
/// raised by an earlier one.
fn merge(action: &mut SignAction, next: SignAction) {
    if !matches!(next, SignAction::None) {
        *action = next;
    }
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    layer: ConfigLayer,
    form: &mut SignForm,
    store: &ConfigStore,
) -> SignScreen {
    match layer {
        ConfigLayer::Unconfigured => SignScreen::prompt_only(prompt(
            ui,
            l10n,
            "gui.connect_to_a_server_to_sign_documents",
            crate::icons::CONNECT,
            "gui.connect",
            SignAction::Connect,
        )),
        ConfigLayer::ServerConfigured => SignScreen::prompt_only(prompt(
            ui,
            l10n,
            "gui.server_connected_log_in_to_sign_documents",
            crate::icons::LOGIN,
            "gui.log_in",
            SignAction::Login,
        )),
        ConfigLayer::FullyConfigured => form.ui(ui, l10n, store),
    }
}

/// A centered message with a single call-to-action button (layers 0 and 1).
fn prompt(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    message_key: &str,
    icon: &str,
    button_key: &str,
    on_click: SignAction,
) -> SignAction {
    let mut action = SignAction::None;
    ui.vertical_centered(|ui| {
        ui.add_space(32.0);
        ui.label(l10n.t(message_key));
        ui.add_space(12.0);
        let label = format!("{icon}  {}", l10n.t(button_key));
        if ui.add(crate::style::primary_button(label)).clicked() {
            action = on_click;
        }
    });
    action
}

#[cfg(test)]
mod tests {
    use super::{default_output, Mode, SignForm};
    use std::path::{Path, PathBuf};

    #[test]
    fn default_output_embedded_appends_signed() {
        assert_eq!(
            default_output(Path::new("/tmp/doc.pdf"), false),
            PathBuf::from("/tmp/doc_signed.pdf")
        );
    }

    #[test]
    fn default_output_detached_appends_p7s() {
        assert_eq!(
            default_output(Path::new("/tmp/doc.pdf"), true),
            PathBuf::from("/tmp/doc.pdf.p7s")
        );
    }

    #[test]
    fn set_pdf_derives_default_output() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        assert_eq!(
            form.default_output(),
            Some(PathBuf::from("/tmp/a_signed.pdf"))
        );
    }

    #[test]
    fn detached_mode_changes_default_output_extension() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        form.mode = Mode::Detached;
        assert_eq!(form.default_output(), Some(PathBuf::from("/tmp/a.pdf.p7s")));
    }

    #[test]
    fn default_output_is_none_without_a_pdf() {
        let form = SignForm::new("noto-sans".to_owned());
        assert_eq!(form.default_output(), None);
    }

    #[test]
    fn embedded_options_carry_high_page_index() {
        use revenant_sign_core::pdf::PageSpec;
        let mut form = SignForm::new("noto-sans".to_owned());
        // A page well past the old fixed cap of 5 (0-based index 41 == page 42).
        form.page = PageSpec::Index(41);
        assert_eq!(form.embedded_options().page, PageSpec::Index(41));
    }

    #[test]
    fn embedded_options_reflect_invisible_and_font() {
        let mut form = SignForm::new("ghea-grapalat".to_owned());
        form.invisible = true;
        let options = form.embedded_options();
        assert!(!options.visible);
        assert_eq!(options.font.as_deref(), Some("ghea-grapalat"));
        assert!(options.image_path.is_none());
    }
}
