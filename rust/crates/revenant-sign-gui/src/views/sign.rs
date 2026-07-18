//! Sign tab. Its content follows the config layer, mirroring the Python client:
//! prompt to connect, prompt to log in, or the signing form.
//!
//! The form itself ([`SignForm`]) is pure UI state; browsing files, spawning the
//! signing job, and revealing the result are side effects the app performs in
//! response to the returned [`SignAction`].

use std::path::{Path, PathBuf};

use eframe::egui;
use revenant_sign_core::appearance::AVAILABLE_FONTS;
use revenant_sign_core::config::ConfigLayer;
use revenant_sign_core::pdf::{PageSpec, Position};
use revenant_sign_core::signing::EmbeddedSignatureOptions;

use crate::i18n::Localizer;
use crate::theme;

/// Position presets offered in the appearance combo, in display order.
const POSITIONS: [Position; 5] = [
    Position::BottomRight,
    Position::BottomLeft,
    Position::BottomCenter,
    Position::TopLeft,
    Position::TopRight,
];

/// Page presets: last, first, then the first five explicit pages (1-based in the
/// UI, 0-based in [`PageSpec::Index`]). Arbitrary higher pages are a later step.
const PAGES: [PageSpec; 7] = [
    PageSpec::Last,
    PageSpec::First,
    PageSpec::Index(0),
    PageSpec::Index(1),
    PageSpec::Index(2),
    PageSpec::Index(3),
    PageSpec::Index(4),
];

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
    /// Open a native save dialog for the output path.
    BrowseOutput,
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
    output_path: String,
    /// Whether the user set the output path by hand; if not, it auto-derives.
    output_edited: bool,
    mode: Mode,
    position: Position,
    page: PageSpec,
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
            output_path: String::new(),
            output_edited: false,
            mode: Mode::Embedded,
            position: Position::BottomRight,
            page: PageSpec::Last,
            font: default_font,
            invisible: false,
            reason: String::new(),
            status: SignStatus::Idle,
            batch: Vec::new(),
            batch_progress: None,
        }
    }

    /// Set the input PDF (from the picker or a drop) and refresh the auto output.
    pub(crate) fn set_pdf(&mut self, path: &Path) {
        self.pdf_path = path.to_string_lossy().into_owned();
        self.status = SignStatus::Idle;
        self.refresh_auto_output();
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

    pub(crate) fn set_output(&mut self, path: &Path) {
        self.output_path = path.to_string_lossy().into_owned();
        self.output_edited = true;
    }

    pub(crate) fn pdf_path(&self) -> &str {
        self.pdf_path.trim()
    }

    pub(crate) fn is_detached(&self) -> bool {
        self.mode == Mode::Detached
    }

    /// The output path to write to: the explicit one, or the derived default.
    pub(crate) fn resolved_output(&self) -> Option<PathBuf> {
        let explicit = self.output_path.trim();
        if !explicit.is_empty() {
            return Some(PathBuf::from(explicit));
        }
        let pdf = self.pdf_path.trim();
        (!pdf.is_empty()).then(|| default_output(Path::new(pdf), self.is_detached()))
    }

    /// The default output path for the current PDF and mode, for the save dialog.
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

    fn refresh_auto_output(&mut self) {
        if self.output_edited {
            return;
        }
        let pdf = self.pdf_path.trim();
        self.output_path = if pdf.is_empty() {
            String::new()
        } else {
            default_output(Path::new(pdf), self.is_detached())
                .to_string_lossy()
                .into_owned()
        };
    }

    fn ui(&mut self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        let mut action = SignAction::None;
        ui.add_space(8.0);

        // Input: a single editable field, or a file list in batch mode.
        if self.is_batch() {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.pdf_file_label"));
                if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
                    action = SignAction::BrowsePdf;
                }
            });
            self.batch_list(ui, l10n);
        } else {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.pdf_file_label"));
                if ui.text_edit_singleline(&mut self.pdf_path).changed() {
                    self.refresh_auto_output();
                }
                if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
                    action = SignAction::BrowsePdf;
                }
            });
        }

        // Signing mode.
        let prev_mode = self.mode;
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.mode, Mode::Embedded, l10n.t("gui.embedded"));
            ui.radio_value(&mut self.mode, Mode::Detached, l10n.t("gui.detached_p7s"));
        });
        if self.mode != prev_mode {
            self.refresh_auto_output();
        }

        let detached = self.is_detached();
        let appearance_enabled = !detached && !self.invisible;

        // Appearance (embedded, visible only).
        ui.add_enabled_ui(!detached, |ui| {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.image_opt_label"));
                ui.add_enabled_ui(appearance_enabled, |ui| {
                    ui.text_edit_singleline(&mut self.image_path);
                    if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
                        action = SignAction::BrowseImage;
                    }
                });
            });
        });

        ui.add_enabled_ui(appearance_enabled, |ui| {
            self.position_combo(ui, l10n);
            self.page_combo(ui, l10n);
            self.font_combo(ui, l10n);
        });

        ui.add_enabled_ui(!detached, |ui| {
            ui.checkbox(&mut self.invisible, l10n.t("gui.invisible_signature"));
        });

        // Reason (embedded metadata).
        ui.add_enabled_ui(!detached, |ui| {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.reason_label"));
                ui.text_edit_singleline(&mut self.reason);
            });
        });

        // Output path (auto-derived per file in batch mode, so hidden there).
        if !self.is_batch() {
            ui.horizontal(|ui| {
                ui.label(l10n.t("gui.output_opt_label"));
                if ui.text_edit_singleline(&mut self.output_path).changed() {
                    self.output_edited = true;
                }
                if ui.button(l10n.t("gui.browse_ellipsis")).clicked() {
                    action = SignAction::BrowseOutput;
                }
            });
        }

        ui.add_space(8.0);
        let busy = matches!(self.status, SignStatus::Signing) || self.batch_progress.is_some();
        let has_input = self.is_batch() || !self.pdf_path.trim().is_empty();
        let label = if self.is_batch() {
            l10n.tf("gui.sign_n_pdfs", &[("n", &self.batch.len().to_string())])
        } else if detached {
            l10n.t("gui.sign_detached").to_owned()
        } else {
            l10n.t("gui.sign_pdf").to_owned()
        };
        if ui
            .add_enabled(!busy && has_input, egui::Button::new(label))
            .clicked()
        {
            action = SignAction::Sign;
        }

        if let SignAction::CancelBatch = self.status_line(ui, l10n) {
            action = SignAction::CancelBatch;
        }
        action
    }

    /// Render the batch file list with per-item remove buttons.
    fn batch_list(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        let mut remove = None;
        egui::ScrollArea::vertical()
            .max_height(90.0)
            .show(ui, |ui| {
                for (index, path) in self.batch.iter().enumerate() {
                    ui.horizontal(|ui| {
                        if ui.small_button(l10n.t("gui.remove")).clicked() {
                            remove = Some(index);
                        }
                        let name = path
                            .file_name()
                            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
                        ui.label(name);
                    });
                }
            });
        if let Some(index) = remove {
            self.batch.remove(index);
        }
    }

    fn position_combo(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.position_label"));
            egui::ComboBox::from_id_salt("sign_position")
                .selected_text(position_label(l10n, self.position))
                .show_ui(ui, |ui| {
                    for pos in POSITIONS {
                        ui.selectable_value(&mut self.position, pos, position_label(l10n, pos));
                    }
                });
        });
    }

    fn page_combo(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.page_label"));
            egui::ComboBox::from_id_salt("sign_page")
                .selected_text(page_label(l10n, self.page))
                .show_ui(ui, |ui| {
                    for page in PAGES {
                        ui.selectable_value(&mut self.page, page, page_label(l10n, page));
                    }
                });
        });
    }

    fn font_combo(&mut self, ui: &mut egui::Ui, l10n: &Localizer) {
        ui.horizontal(|ui| {
            ui.label(l10n.t("gui.font_label"));
            egui::ComboBox::from_id_salt("sign_font")
                .selected_text(&self.font)
                .show_ui(ui, |ui| {
                    for font in AVAILABLE_FONTS {
                        ui.selectable_value(&mut self.font, font.to_owned(), font);
                    }
                });
        });
    }

    /// Render the progress/result area. Returns [`SignAction::CancelBatch`] when
    /// the batch cancel button is pressed.
    fn status_line(&self, ui: &mut egui::Ui, l10n: &Localizer) -> SignAction {
        ui.add_space(4.0);
        if let Some(progress) = &self.batch_progress {
            return batch_progress_line(ui, l10n, progress);
        }
        match &self.status {
            SignStatus::Idle => {}
            SignStatus::Signing => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(l10n.t("gui.signing_ellipsis"));
                });
            }
            SignStatus::Done(message) => {
                ui.colored_label(theme::OK, message);
            }
            SignStatus::Failed(message) => {
                ui.colored_label(theme::ERROR, message);
            }
        }
        SignAction::None
    }
}

/// The batch progress bar, current-file line, and cancel button.
fn batch_progress_line(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    progress: &BatchProgress,
) -> SignAction {
    // `u16::from` is lossless, sidestepping the float-cast precision lint.
    let done = u16::try_from(progress.current.saturating_sub(1)).unwrap_or(u16::MAX);
    let total = u16::try_from(progress.total).unwrap_or(u16::MAX);
    let fraction = if total == 0 {
        0.0
    } else {
        f32::from(done) / f32::from(total)
    };
    ui.add(egui::ProgressBar::new(fraction).show_percentage());
    ui.label(l10n.tf(
        "gui.signing_n_of_total_filename",
        &[
            ("n", &progress.current.to_string()),
            ("total", &progress.total.to_string()),
            ("filename", &progress.filename),
        ],
    ));
    let mut action = SignAction::None;
    if ui.button(l10n.t("gui.cancel")).clicked() {
        action = SignAction::CancelBatch;
    }
    action
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

fn position_label(l10n: &Localizer, position: Position) -> &str {
    match position {
        Position::BottomRight => l10n.t("gui.pos_bottom_right"),
        Position::BottomLeft => l10n.t("gui.pos_bottom_left"),
        Position::BottomCenter => l10n.t("gui.pos_bottom_center"),
        Position::TopLeft => l10n.t("gui.pos_top_left"),
        Position::TopRight => l10n.t("gui.pos_top_right"),
    }
}

fn page_label(l10n: &Localizer, page: PageSpec) -> String {
    match page {
        PageSpec::Last => l10n.t("gui.page_last").to_owned(),
        PageSpec::First => l10n.t("gui.page_first").to_owned(),
        PageSpec::Index(index) => (index + 1).to_string(),
    }
}

pub(crate) fn show(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    layer: ConfigLayer,
    form: &mut SignForm,
) -> SignAction {
    match layer {
        ConfigLayer::Unconfigured => prompt(
            ui,
            l10n,
            "gui.connect_to_a_server_to_sign_documents",
            "gui.connect",
            SignAction::Connect,
        ),
        ConfigLayer::ServerConfigured => prompt(
            ui,
            l10n,
            "gui.server_connected_log_in_to_sign_documents",
            "gui.log_in",
            SignAction::Login,
        ),
        ConfigLayer::FullyConfigured => form.ui(ui, l10n),
    }
}

/// A centered message with a single call-to-action button (layers 0 and 1).
fn prompt(
    ui: &mut egui::Ui,
    l10n: &Localizer,
    message_key: &str,
    button_key: &str,
    on_click: SignAction,
) -> SignAction {
    let mut action = SignAction::None;
    ui.vertical_centered(|ui| {
        ui.add_space(32.0);
        ui.label(l10n.t(message_key));
        ui.add_space(12.0);
        if ui.button(l10n.t(button_key)).clicked() {
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
    fn set_pdf_auto_derives_output() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/tmp/a_signed.pdf"))
        );
    }

    #[test]
    fn switching_to_detached_updates_auto_output() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        form.mode = Mode::Detached;
        form.refresh_auto_output();
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/tmp/a.pdf.p7s"))
        );
    }

    #[test]
    fn manual_output_survives_mode_switch() {
        let mut form = SignForm::new("noto-sans".to_owned());
        form.set_pdf(Path::new("/tmp/a.pdf"));
        form.set_output(Path::new("/custom/out.pdf"));
        form.mode = Mode::Detached;
        form.refresh_auto_output();
        assert_eq!(
            form.resolved_output(),
            Some(PathBuf::from("/custom/out.pdf"))
        );
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
