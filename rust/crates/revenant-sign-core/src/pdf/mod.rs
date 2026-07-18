//! PDF signature preparation, incremental-update assembly, and verification.
//!
//! Reserve an empty signature field via a true incremental update (the original
//! bytes are preserved exactly, new objects appended after `%%EOF`), compute the
//! ByteRange hash to send to the appliance, splice the returned CMS into the
//! reserved `/Contents`, and verify signed documents. The CMS *reading* layer
//! lives in [`crate::cms`]; the visual appearance in [`crate::appearance`].
//!
//! Reading existing PDF structure goes through [`reader::PdfReader`] (backed by
//! `lopdf`); everything written is assembled as raw bytes so the signed byte
//! range is exact.

mod builder;
mod incremental;
mod objects;
mod position;
mod reader;
mod render;
mod verify;

pub use builder::{compute_byterange_hash, insert_cms, prepare_pdf_with_sig_field, PrepareOptions};
pub use incremental::{
    assemble_incremental_update, build_xref_and_trailer, build_xref_stream, detect_xref_stream,
    find_root_obj_num, find_startxref_offset, patch_byterange, PreparedPdf, UpdatePlan,
};
pub use objects::{
    build_catalog_override, build_page_override, pdf_string, FontObjNums, FormObjNums,
    SigObjectNums, VisibleObjNums, ANNOT_FLAGS_SIG_WIDGET, BYTERANGE_PLACEHOLDER, CMS_HEX_SIZE,
    CMS_RESERVED_SIZE,
};
pub use position::{
    compute_sig_rect, resolve_page_index, PageSpec, Position, SigRect, SIG_HEIGHT, SIG_MARGIN_H,
    SIG_MARGIN_V, SIG_WIDTH,
};
pub use reader::{ObjRef, PageInfo, PdfReader};
// `render` is internal machinery: its appearance-object builders are used only
// by `builder`, so nothing from it is re-exported here.
pub use verify::{
    verify_all_embedded_signatures, verify_detached_signature, verify_embedded_signature,
    ChainValidator, VerificationResult,
};
