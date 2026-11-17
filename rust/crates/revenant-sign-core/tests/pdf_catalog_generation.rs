use lopdf::{xref::XrefEntry, Document};
use revenant_sign_core::pdf::{prepare_pdf_with_sig_field, PrepareOptions};

#[test]
fn preserves_catalog_generation_in_the_incremental_update() -> Result<(), Box<dyn std::error::Error>>
{
    let cases: &[(&[u8], u16, bool)] = &[
        (
            include_bytes!("../src/pdf/testdata/catalog_gen_1.pdf"),
            1,
            true,
        ),
        (
            include_bytes!("../src/pdf/testdata/catalog_gen_513.pdf"),
            513,
            false,
        ),
    ];
    for &(input, generation, visible) in cases {
        let options = PrepareOptions {
            visible,
            ..Default::default()
        };
        let prepared = prepare_pdf_with_sig_field(input, &options)?;
        assert!(prepared.bytes.starts_with(input));

        let doc = Document::load_mem(&prepared.bytes)?;
        let root = doc.trailer.get(b"Root")?.as_reference()?;
        assert_eq!(root, (1, generation));
        let Some(XrefEntry::Normal {
            offset,
            generation: xref_gen,
        }) = doc.reference_table.get(root.0)
        else {
            panic!("expected an in-use catalog in the new xref")
        };
        assert_eq!(*xref_gen, generation);
        let offset = *offset as usize;
        assert!(offset >= input.len());
        assert!(prepared.bytes[offset..].starts_with(format!("1 {generation} obj\n").as_bytes()));

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
