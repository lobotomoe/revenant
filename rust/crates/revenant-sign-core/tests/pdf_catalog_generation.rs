use std::num::NonZeroU32;

use lopdf::{xref::XrefEntry, Document, ObjectId};
use revenant_sign_core::pdf::{
    build_catalog_override, find_root_obj_num, prepare_pdf_with_sig_field, ObjRef, PdfReader,
    PrepareOptions,
};

const TWO_REVISIONS: &[u8] = include_bytes!("../src/pdf/testdata/catalog_two_revisions.pdf");

#[test]
fn preserves_current_catalog_in_the_incremental_update() -> Result<(), Box<dyn std::error::Error>> {
    let cases: &[(&[u8], ObjectId, bool)] = &[
        (
            include_bytes!("../src/pdf/testdata/catalog_gen_1.pdf"),
            (1, 1),
            true,
        ),
        (
            include_bytes!("../src/pdf/testdata/catalog_gen_513.pdf"),
            (1, 513),
            false,
        ),
        (TWO_REVISIONS, (7, 0), true),
    ];
    for &(input, expected_root, visible) in cases {
        let options = PrepareOptions {
            visible,
            ..Default::default()
        };
        let prepared = prepare_pdf_with_sig_field(input, &options)?;
        assert!(prepared.bytes.starts_with(input));

        let doc = Document::load_mem(&prepared.bytes)?;
        let root = doc.trailer.get(b"Root")?.as_reference()?;
        assert_eq!(root, expected_root);
        assert_eq!(find_root_obj_num(input)?, ObjRef::new(root.0, root.1));
        let Some(XrefEntry::Normal {
            offset,
            generation: xref_gen,
        }) = doc.reference_table.get(root.0)
        else {
            panic!("expected an in-use catalog in the new xref")
        };
        assert_eq!(*xref_gen, root.1);
        let offset = *offset as usize;
        assert!(offset >= input.len());
        assert!(
            prepared.bytes[offset..].starts_with(format!("{} {} obj\n", root.0, root.1).as_bytes())
        );

        let catalog = doc.catalog()?;
        let fields = catalog
            .get(b"AcroForm")?
            .as_dict()?
            .get(b"Fields")?
            .as_array()?;
        let annots = doc.get_dictionary((3, 0))?.get(b"Annots")?.as_array()?;
        assert_eq!(fields.len(), 1);
        assert_eq!(fields, annots);
        let widget = doc.get_dictionary(fields[0].as_reference()?)?;
        assert_eq!(widget.get(b"FT")?.as_name()?, b"Sig");
        assert_eq!(
            catalog
                .get(b"Names")?
                .as_dict()?
                .get(b"EmbeddedFiles")?
                .as_reference()?,
            (4, 0)
        );
    }
    Ok(())
}

#[test]
fn catalog_helpers_accept_inferred_u32_conversions() -> revenant_sign_core::Result<()> {
    let reader = PdfReader::open(include_bytes!("../src/pdf/testdata/catalog_gen_1.pdf"))?;
    let root = NonZeroU32::new(1).unwrap();
    let catalog = build_catalog_override(&reader, root.into(), 9)?;
    assert!(catalog.starts_with(b"1 1 obj\n"));
    assert_eq!(
        reader.catalog_override_with_sig_field(root.into(), 9)?,
        catalog
    );
    Ok(())
}
