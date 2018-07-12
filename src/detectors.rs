use regex::Regex;

lazy_static! {
    pub static ref EMAIL_REGEX: Regex = Regex::new(
        r#"(?x)
            \b[a-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(\\.[a-z0-9-]+)\b
    "#
    ).unwrap();
    pub static ref IPV4_REGEX: Regex = Regex::new(
        r#"(?x)
            \b(
                (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.
                (25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
            )\b
    "#
    ).unwrap();
    pub static ref IPV6_REGEX: Regex = Regex::new(
        r#"(?xi)
            (((?=.*(::))(?!.*\3.+\3))\3?|([\dA-F]{1,4}(\3|:\b|$)|\2))
            (?4){5}((?4){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})
    "#
    ).unwrap();
    pub static ref CREDITCARD_REGEX: Regex = Regex::new(
        r#"(?x)
            \d{4}[- ]?\d{4,6}[- ]?\d{4,5}(?:[- ]?\d{4})
    "#
    ).unwrap();
}
