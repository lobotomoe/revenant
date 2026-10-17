//! The languages store listings are written in, and each shot's copy in them.
//!
//! The terms follow the app's own catalogs (`i18n/locales/*.po`), so a caption
//! names a control the way the screenshot beside it shows it.

/// A language a store listing is published in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Locale {
    En,
    Ru,
    Hy,
}

impl Locale {
    /// The app's language code, as its config and catalogs name it.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Ru => "ru",
            Locale::Hy => "hy",
        }
    }

    /// The mark that ends a sentence: Armenian has its own full stop.
    pub(crate) fn full_stop(self) -> &'static str {
        match self {
            Locale::En | Locale::Ru => ".",
            Locale::Hy => "։",
        }
    }
}

/// One piece of listing copy in every language a listing is published in.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Text {
    pub(crate) en: &'static str,
    pub(crate) ru: &'static str,
    pub(crate) hy: &'static str,
}

impl Text {
    pub(crate) fn get(&self, locale: Locale) -> &'static str {
        match locale {
            Locale::En => self.en,
            Locale::Ru => self.ru,
            Locale::Hy => self.hy,
        }
    }
}

pub(crate) const SIGN_HEADLINE: Text = Text {
    en: "Sign PDFs with your CoSign account",
    ru: "Подписывайте PDF своей учётной записью CoSign",
    hy: "Ստորագրեք PDF-ները ձեր CoSign հաշվով",
};
pub(crate) const SIGN_SUBLINE: Text = Text {
    en: "Embedded or detached signatures, with a visible stamp on any page.",
    ru: "Встроенные или отделённые подписи с видимым штампом на любой странице.",
    hy: "Ներդրված կամ անջատված ստորագրություններ՝ տեսանելի կնիքով ցանկացած էջում։",
};

pub(crate) const BATCH_HEADLINE: Text = Text {
    en: "Sign a whole stack at once",
    ru: "Подписывайте сразу целую пачку",
    hy: "Ստորագրեք մի ամբողջ փաթեթ միանգամից",
};
pub(crate) const BATCH_SUBLINE: Text = Text {
    en: "Drop several PDFs and sign them all in one pass.",
    ru: "Перетащите несколько PDF и подпишите их все за один раз.",
    hy: "Քաշեք մի քանի PDF և ստորագրեք բոլորը մեկ անգամով։",
};

pub(crate) const VERIFY_HEADLINE: Text = Text {
    en: "Verify signed PDFs",
    ru: "Проверяйте подписанные PDF",
    hy: "Ստուգեք ստորագրված PDF-ները",
};
pub(crate) const VERIFY_SUBLINE: Text = Text {
    en: "Integrity, signer, and certificate trust, checked in one step.",
    ru: "Целостность, подписант и доверие к сертификату проверяются за один шаг.",
    hy: "Ամբողջականությունը, ստորագրողը և վկայագրի վստահելիությունը՝ մեկ քայլով։",
};

pub(crate) const SERVER_HEADLINE: Text = Text {
    en: "EKENG profile built in",
    ru: "Профиль EKENG уже встроен",
    hy: "EKENG-ի պրոֆիլն արդեն ներկառուցված է",
};
pub(crate) const SERVER_SUBLINE: Text = Text {
    en: "Or connect to your organization's own signing server.",
    ru: "Или подключитесь к собственному серверу подписи вашей организации.",
    hy: "Կամ միացեք ձեր կազմակերպության սեփական ստորագրման սերվերին։",
};

pub(crate) const LOGIN_HEADLINE: Text = Text {
    en: "Your password, kept by the system keychain",
    ru: "Пароль хранится в системном хранилище",
    hy: "Գաղտնաբառը պահվում է համակարգային պահոցում",
};
pub(crate) const LOGIN_SUBLINE: Text = Text {
    en: "Opt in once, and the operating system stores it for you.",
    ru: "Включите один раз, и операционная система сохранит его за вас.",
    hy: "Միացրեք մեկ անգամ, և օպերացիոն համակարգը կպահի այն ձեր փոխարեն։",
};

// The fictional documents the shots sign and verify, named in the listing's
// language so the window reads as a local user's would.

pub(crate) const DOCUMENT: Text = Text {
    en: "Lease agreement.pdf",
    ru: "Договор аренды.pdf",
    hy: "Վարձակալության պայմանագիր.pdf",
};
pub(crate) const SIGNED_DOCUMENT: Text = Text {
    en: "Lease agreement_signed.pdf",
    ru: "Договор аренды_signed.pdf",
    hy: "Վարձակալության պայմանագիր_signed.pdf",
};
pub(crate) const BATCH: [Text; 3] = [
    DOCUMENT,
    Text {
        en: "Annex 1 - Inventory.pdf",
        ru: "Приложение 1 - Опись имущества.pdf",
        hy: "Հավելված 1 - Գույքի ցուցակ.pdf",
    },
    Text {
        en: "Annex 2 - Payment schedule.pdf",
        ru: "Приложение 2 - График платежей.pdf",
        hy: "Հավելված 2 - Վճարումների ժամանակացույց.pdf",
    },
];
